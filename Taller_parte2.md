# Pipeline CI/CD — Security Hardening

## Parte 2B: Seguridad en el Pipeline de Despliegue en GKE

---

## 1. Objetivos de esta Práctica

Partiendo del pipeline funcional de la Práctica 1 (GitHub Actions → Artifact Registry → GKE), añadimos tres capas de seguridad de forma incremental. Cada paso se puede aplicar, probar y verificar de forma independiente antes de pasar al siguiente.

| Paso | Mejora | Problema que resuelve | Resultado |
|---|---|---|---|
| 1 | **Escaneo con Trivy** | Imágenes con vulnerabilidades llegan a producción | El pipeline se detiene si se detectan CVEs críticas o altas |
| 2 | **Workload Identity Federation** | La clave JSON de la SA es un secreto estático de larga duración | Autenticación sin secretos, basada en tokens OIDC efímeros |
| 3 | **Kubernetes Secrets** | La `GOOGLE_API_KEY` se inyecta en el `.env` y queda embebida en la imagen | La clave vive como Secret de K8s, nunca toca la imagen Docker |

### Arquitectura de Seguridad (Estado Final)

```
Developer Push (main)
        ↓
GitHub Actions Runner
  ├─ OIDC Token (GitHub) ←→ Workload Identity Federation (GCP)
  │   └─ Sin clave JSON — token efímero de corta duración
  ├─ Build imágenes
  ├─ Trivy Scan (CRITICAL/HIGH → bloquea pipeline)
  ├─ Push imágenes → Artifact Registry
  ├─ Crear K8s Secret (GOOGLE_API_KEY) 
  └─ Ansible → kubectl apply → GKE
        ↓
  GKE Autopilot
    ├─ Pod backend ← lee GOOGLE_API_KEY desde K8s Secret (no del .env)
    └─ Pod frontend
```

---

## 2. Prerrequisitos

- Práctica 1 completada y funcionando (pipeline despliega en GKE).
- Acceso a Cloud Shell o terminal con `gcloud` configurado.
- Repositorio en GitHub con permisos de administrador (necesario para el Paso 2).

```bash
export PROJECT_ID=$(gcloud config get-value project)
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
export REGION=us-central1
export CLUSTER_NAME=test-cluster-a
export GITHUB_ORG="tu-usuario"    # tu usuario o nombre de organización en GitHub
export GITHUB_REPO="tu-repo"             # nombre del repositorio
```

---

## Paso 1 — Escaneo de Vulnerabilidades con Trivy

### ¿Qué es y por qué?

Trivy es un escáner de seguridad open-source mantenido por Aqua Security. Analiza imágenes Docker, ficheros del sistema y configuraciones IaC en busca de CVEs (vulnerabilidades conocidas), secretos expuestos y misconfigurations.

Integrándolo en el pipeline, las imágenes se escanean **después del build y antes del push**. Si se detectan vulnerabilidades CRITICAL o HIGH, el pipeline se detiene y las imágenes no llegan a Artifact Registry ni a producción.

### 1.1 — Pasos de Trivy en el Workflow

Se añaden dos pasos de escaneo (uno por imagen), justo después de cada build y antes de los push. Este es el cambio más sencillo: solo se añaden steps al workflow existente.

```yaml
      # ─────────────────────────────────────
      #  Escaneo de seguridad — Backend
      # ─────────────────────────────────────
      - name: Trivy scan backend image
        uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: '${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      # ─────────────────────────────────────
      #  Escaneo de seguridad — Frontend
      # ─────────────────────────────────────
      - name: Trivy scan frontend image
        uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: '${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true
```

**Parámetros clave:**

| Parámetro | Valor | Función |
|---|---|---|
| `exit-code` | `1` | Falla el pipeline si encuentra vulnerabilidades |
| `severity` | `CRITICAL,HIGH` | Solo bloquea en severidades altas (ignora MEDIUM/LOW) |
| `ignore-unfixed` | `true` | Ignora CVEs sin parche disponible (evita falsos bloqueos) |
| `format` | `table` | Salida legible en los logs del workflow |

> 💡 **`ignore-unfixed: true`** es importante: sin esto, Trivy puede bloquear el pipeline por vulnerabilidades en paquetes base del SO que aún no tienen parche, lo cual no es accionable por el desarrollador.


### 1.2 — Verificar Trivy (opcional, solo si vas bien de tiempo)

Forzar un fallo para comprobar que el pipeline se detiene:

```dockerfile
# En backend/Dockerfile, añadir temporalmente:
FROM python:3.9-slim
# (una imagen antigua con CVEs conocidas)
```

El paso de Trivy debe fallar con una tabla de vulnerabilidades y el pipeline debe detenerse antes del push. Revertir el cambio después de verificar.

---

## Paso 2 — Workload Identity Federation (Eliminar clave JSON)

### ¿Qué es y por qué?

En la Práctica 2, GitHub Actions se autentica en GCP usando una clave JSON (`GCP_SA_KEY`) almacenada como secreto de GitHub. Esta clave es un secreto estático de larga duración: si alguien la obtiene, tiene acceso permanente hasta que se revoque manualmente.

Workload Identity Federation elimina este riesgo. En lugar de una clave JSON, GitHub Actions obtiene un token OIDC efímero (dura ~1 hora) que GCP valida directamente contra el proveedor de identidad de GitHub. No hay credenciales que rotar, filtrar o gestionar.

### 2.1 — Habilitar APIs Necesarias

```bash
gcloud services enable \
  iamcredentials.googleapis.com \
  sts.googleapis.com
```

### 2.2 — Crear el Workload Identity Pool

El pool es un contenedor lógico que agrupa identidades externas (en este caso, de GitHub).

```bash
gcloud iam workload-identity-pools create github-actions-pool \
  --location="global" \
  --display-name="GitHub Actions Pool" \
  --description="Pool para autenticación de GitHub Actions via OIDC"
```

### 2.3 — Crear el OIDC Provider

El provider conecta el pool con el sistema OIDC de GitHub y mapea las claims del token JWT a atributos que GCP puede evaluar.

```bash
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --display-name="GitHub OIDC Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="\
google.subject=assertion.sub,\
attribute.repository=assertion.repository,\
attribute.repository_owner=assertion.repository_owner,\
attribute.ref=assertion.ref" \
  --attribute-condition="assertion.repository_owner=='${GITHUB_ORG}'"
```

**Desglose de los parámetros:**

| Parámetro | Función |
|---|---|
| `--issuer-uri` | URL del proveedor OIDC de GitHub Actions |
| `--attribute-mapping` | Traduce claims del JWT de GitHub a atributos de GCP |
| `--attribute-condition` | **Restricción de seguridad**: solo acepta tokens de tu organización/usuario |

>  **Seguridad:** El `attribute-condition` es crítico. Sin él, *cualquier* repositorio de GitHub podría autenticarse con tu pool. Con la condición `repository_owner=='tu-org'`, solo los workflows de tus repos pueden obtener tokens.

### 2.4 — Vincular la Service Account al Pool

Permitimos que las identidades del pool impersonen la Service Account `github-ci` que ya tenemos:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  github-ci@${PROJECT_ID}.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions-pool/attribute.repository/${GITHUB_ORG}/${GITHUB_REPO}"
```

>  Esto restringe aún más: solo el repositorio específico puede impersonar la SA.

### 2.5 — Obtener el Identificador del Provider

Necesitamos el nombre completo del provider para configurar GitHub Actions:

```bash
gcloud iam workload-identity-pools providers describe github-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --format="value(name)"
```

El resultado tendrá este formato:

```
projects/123456789/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
```

Guarda este valor — lo necesitarás como secreto de GitHub.

### 2.6 — Actualizar Secretos en GitHub

**Eliminar:**
- `GCP_SA_KEY` ← ya no necesitamos la clave JSON

**Añadir:**
| Secreto | Valor |
|---|---|
| `WORKLOAD_IDENTITY_PROVIDER` | `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider` |
| `SERVICE_ACCOUNT_EMAIL` | `github-ci@PROJECT_ID.iam.gserviceaccount.com` |

(aquí si que hay que remplazar los valores por los reales de tu entorno)

**Mantener sin cambios:**
- `PROJECT_ID`
- `GOOGLE_API_KEY`

### 2.7 — Cambios en el Workflow

Dos modificaciones en el `.github/workflows/build-deploy.yml`:

**a) Añadir permisos OIDC** (a nivel de workflow, antes de `jobs`):

```yaml
permissions:
  contents: read
  id-token: write
```

**b) Cambiar el step de autenticación:**

```yaml
      # ANTES (clave JSON):
      # - name: Authenticate to GCP
      #   uses: google-github-actions/auth@v2
      #   with:
      #     credentials_json: '${{ secrets.GCP_SA_KEY }}'

      # DESPUÉS (WIF):
      - name: Authenticate to GCP via WIF
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.SERVICE_ACCOUNT_EMAIL }}
```

### 2.8 — Verificar WIF

En los logs del workflow de GitHub Actions, el paso "Authenticate to GCP via WIF" debe mostrar:

```
Successfully authenticated via Workload Identity Federation
```

No debe aparecer ninguna referencia a `credentials_json` ni a claves JSON.

>  **Nota:** Los cambios de IAM pueden tardar hasta 5 minutos en propagarse. Si el primer intento falla, esperar y reintentar.

### 2.9 — Eliminar la Clave JSON Antigua

Una vez verificado que WIF funciona, revoca la clave JSON:

```bash
# Listar claves
gcloud iam service-accounts keys list \
  --iam-account=github-ci@${PROJECT_ID}.iam.gserviceaccount.com

# Eliminar la clave (sustituir KEY_ID)
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=github-ci@${PROJECT_ID}.iam.gserviceaccount.com
```

---

## Paso 3 — Kubernetes Secrets (Sacar API Key de la Imagen)

### ¿Qué es y por qué?

En la Práctica 2, la `GOOGLE_API_KEY` se escribe en `backend/.env` durante el build y queda embebida dentro de la imagen Docker. Esto significa que cualquiera con acceso a la imagen (Artifact Registry, caché del runner, etc.) puede extraer la clave.

La solución es crear un Kubernetes Secret y montarlo como variable de entorno en el pod del backend. La clave nunca toca la imagen.

Este paso es el que toca más piezas: workflow, manifiesto K8s, playbook de Ansible y potencialmente el código del backend.

### 3.1 — Nuevo Manifiesto: `k8s/backend-secret.yaml`

Este fichero se añade al repositorio. El valor real del secreto se inyecta dinámicamente desde el pipeline (no se hardcodea en el YAML).

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: backend-secrets
  namespace: ucm-master
type: Opaque
data:
  GOOGLE_API_KEY: PLACEHOLDER
```

> ⚠️ `PLACEHOLDER` será sustituido por el valor real (codificado en base64) durante el despliegue con Ansible.

### 3.2 — Modificar `k8s/backend.yaml`

Añadimos la referencia al Secret como variable de entorno y eliminamos la dependencia del `.env`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-backend
  namespace: ucm-master
  labels:
    app: agent-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-backend
  template:
    metadata:
      labels:
        app: agent-backend
    spec:
      containers:
        - name: agent-backend
          image: us-central1-docker.pkg.dev/PROJECT_ID/agent-repo/agent-backend:IMAGE_TAG
          ports:
            - containerPort: 80
          env:
            - name: GOOGLE_API_KEY
              valueFrom:
                secretKeyRef:
                  name: backend-secrets
                  key: GOOGLE_API_KEY
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: 250m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: agent-backend
  namespace: ucm-master
spec:
  selector:
    app: agent-backend
  ports:
    - port: 80
      targetPort: 80
  type: ClusterIP
```

### 3.3 — Modificar `backend/Dockerfile`

El Dockerfile actual contiene `COPY .env .` que copia el fichero `.env` dentro de la imagen. Hay que eliminarla:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY crypto_tools.py .
# COPY .env .          ← ELIMINAR esta línea (la API key ahora viene del K8s Secret)

EXPOSE 80
CMD ["python", "app.py"]
```

>  **Importante:** Si se mantiene `COPY .env .` y no existe el fichero, el build de Docker falla con `failed to calculate checksum: "/.env": not found`.

### 3.4 — Consideraciones sobre el Backend

La aplicación Python del backend debe leer `GOOGLE_API_KEY` desde las variables de entorno del sistema (con `os.environ` o `os.getenv`), no desde un fichero `.env`. Si el backend usa `python-dotenv` con `load_dotenv()`, este paquete no falla si el `.env` no existe y respeta las variables de entorno del sistema, por lo que debería funcionar sin cambios. Si se quiere ser explícito, se puede usar `load_dotenv(override=False)` para garantizar que las variables del sistema tienen prioridad.

### 3.5 — Cambios en el Workflow

**Eliminar** el paso `Create backend .env`:

```yaml
      # ELIMINAR este paso:
      # - name: Create backend .env
      #   run: |
      #     echo "GOOGLE_API_KEY=${{ secrets.GOOGLE_API_KEY }}" > backend/.env
```

**Añadir** `GOOGLE_API_KEY` como variable de entorno en el paso de Ansible:

```yaml
      - name: Deploy to GKE via Ansible
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
          USE_GKE_GCLOUD_AUTH_PLUGIN: "True"
        run: |
          ansible-playbook ansible/deploy-gke.yml \
            --extra-vars "image_tag=${{ github.sha }}"
```

### 3.6 — Verificar Kubernetes Secrets

```bash
# Verificar que el Secret existe
kubectl get secret backend-secrets -n ucm-master

# Verificar que el pod usa el Secret
kubectl describe pod -l app=agent-backend -n ucm-master | grep -A5 "Environment"
```

La salida debe mostrar:

```
Environment:
  GOOGLE_API_KEY:  <set to the key 'GOOGLE_API_KEY' in secret 'backend-secrets'>
```

### 3.7 — Verificar que la imagen NO contiene la API key

```bash
# Descargar y examinar la imagen
docker pull us-central1-docker.pkg.dev/$PROJECT_ID/agent-repo/agent-backend:latest

# Buscar la API key en las capas de la imagen
docker history us-central1-docker.pkg.dev/$PROJECT_ID/agent-repo/agent-backend:latest
docker run --rm us-central1-docker.pkg.dev/$PROJECT_ID/agent-repo/agent-backend:latest cat .env 2>/dev/null || echo "No .env found ✅"
```

---

## Paso 4 — Playbook de Ansible Actualizado

El playbook se modifica para crear el Kubernetes Secret dinámicamente antes de aplicar los deployments.

### `ansible/deploy-gke.yml` (Actualizado)

```yaml
---
- name: Deploy Crypto Chatbot to GKE (Secured)
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    project_id: "{{ lookup('env', 'PROJECT_ID') }}"
    google_api_key: "{{ lookup('env', 'GOOGLE_API_KEY') }}"
    region: "us-central1"
    cluster_name: "test-cluster-a"
    registry_base: "us-central1-docker.pkg.dev/{{ project_id }}/agent-repo"
    namespace: "ucm-master"
    k8s_dir: "{{ playbook_dir }}/../k8s"
    # image_tag se pasa como --extra-vars

  tasks:

    # ─────────────────────────────────────
    # Obtener credenciales del clúster GKE
    # ─────────────────────────────────────
    - name: Obtener credenciales de GKE
      command: >
        gcloud container clusters get-credentials {{ cluster_name }}
          --region {{ region }}
          --project {{ project_id }}
      changed_when: false

    # ─────────────────────────────────────
    # Crear namespace (idempotente)
    # ─────────────────────────────────────
    - name: Aplicar namespace
      command: kubectl apply -f {{ k8s_dir }}/namespace.yaml
      changed_when: false

    # ─────────────────────────────────────
    # Crear/Actualizar Kubernetes Secret
    # ─────────────────────────────────────
    - name: Crear Secret con GOOGLE_API_KEY
      shell: |
        kubectl create secret generic backend-secrets \
          --namespace={{ namespace }} \
          --from-literal=GOOGLE_API_KEY={{ google_api_key }} \
          --dry-run=client -o yaml | kubectl apply -f -
      changed_when: false

    # ─────────────────────────────────────
    # Preparar manifiestos con imagen real
    # ─────────────────────────────────────
    - name: Crear directorio temporal para manifiestos
      tempfile:
        state: directory
        suffix: k8s-deploy
      register: tmp_dir

    - name: Procesar backend.yaml con imagen correcta
      shell: |
        sed -e 's|PROJECT_ID|{{ project_id }}|g' \
            -e 's|IMAGE_TAG|{{ image_tag }}|g' \
            {{ k8s_dir }}/backend.yaml > {{ tmp_dir.path }}/backend.yaml

    - name: Procesar frontend.yaml con imagen correcta
      shell: |
        sed -e 's|PROJECT_ID|{{ project_id }}|g' \
            -e 's|IMAGE_TAG|{{ image_tag }}|g' \
            {{ k8s_dir }}/frontend.yaml > {{ tmp_dir.path }}/frontend.yaml

    # ─────────────────────────────────────
    # Desplegar en GKE
    # ─────────────────────────────────────
    - name: Desplegar backend
      command: kubectl apply -f {{ tmp_dir.path }}/backend.yaml
      register: backend_deploy

    - name: Desplegar frontend
      command: kubectl apply -f {{ tmp_dir.path }}/frontend.yaml
      register: frontend_deploy

    - name: Mostrar resultado del despliegue
      debug:
        msg:
          - "Backend: {{ backend_deploy.stdout }}"
          - "Frontend: {{ frontend_deploy.stdout }}"

    # ─────────────────────────────────────
    # Verificar estado del despliegue
    # (Autopilot puede tardar varios minutos
    #  en aprovisionar nodos la primera vez)
    # ─────────────────────────────────────
    - name: Esperar a que el backend esté disponible
      command: >
        kubectl get deployment agent-backend -n {{ namespace }}
          -o jsonpath='{.status.availableReplicas}'
      register: backend_status
      retries: 20
      delay: 30
      until: backend_status.stdout | default('0') | int >= 1
      changed_when: false

    - name: Esperar a que el frontend esté disponible
      command: >
        kubectl get deployment agent-frontend -n {{ namespace }}
          -o jsonpath='{.status.availableReplicas}'
      register: frontend_status
      retries: 20
      delay: 30
      until: frontend_status.stdout | default('0') | int >= 1
      changed_when: false

    - name: Obtener pods en ejecución
      command: kubectl get pods -n {{ namespace }} -o wide
      register: pod_status

    - name: Mostrar estado de pods
      debug:
        msg: "{{ pod_status.stdout_lines }}"

    # ─────────────────────────────────────
    # Obtener IP externa del frontend
    # ─────────────────────────────────────
    - name: Obtener servicio frontend
      command: kubectl get svc agent-frontend -n {{ namespace }} -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
      register: frontend_ip
      retries: 10
      delay: 15
      until: frontend_ip.stdout | length > 0

    - name: Mostrar URL de acceso
      debug:
        msg: "🚀 Chatbot disponible en: http://{{ frontend_ip.stdout }}"

    # ─────────────────────────────────────
    # Limpieza
    # ─────────────────────────────────────
    - name: Eliminar directorio temporal
      file:
        path: "{{ tmp_dir.path }}"
        state: absent
```

**Cambio clave:** La tarea `Crear Secret con GOOGLE_API_KEY` usa el patrón `--dry-run=client -o yaml | kubectl apply -f -` que es idempotente: crea el Secret si no existe, o lo actualiza si ya existe, sin errores.

---

## Paso 5 — Workflow Completo (Estado Final con las 3 Capas)

### `.github/workflows/build-deploy.yml`

```yaml
name: Build and Deploy Crypto Chatbot to GKE (Secured)

on:
  push:
    branches: [main]

env:
  REGION: us-central1
  REGISTRY: us-central1-docker.pkg.dev
  REPO: agent-repo
  CLUSTER_NAME: test-cluster-a

# ─────────────────────────────────────
# Permiso OIDC para Workload Identity Federation
# ─────────────────────────────────────
permissions:
  contents: read
  id-token: write

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest

    steps:
      # ─────────────────────────────────────
      # Checkout del código
      # ─────────────────────────────────────
      - name: Checkout repo
        uses: actions/checkout@v4

      # ─────────────────────────────────────
      # Autenticación en GCP via Workload Identity Federation
      # (Sin clave JSON — usa OIDC token efímero)
      # ─────────────────────────────────────
      - name: Authenticate to GCP via WIF
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ secrets.SERVICE_ACCOUNT_EMAIL }}

      - name: Set up Cloud SDK with kubectl
        uses: google-github-actions/setup-gcloud@v2
        with:
          install_components: 'kubectl,gke-gcloud-auth-plugin'

      - name: Configure Docker for Artifact Registry
        run: |
          gcloud auth configure-docker ${{ env.REGISTRY }}

      # ─────────────────────────────────────
      # Build — Backend (Python)
      # (Ya NO se crea el .env — la API key
      #  se inyecta como K8s Secret)
      # ─────────────────────────────────────
      - name: Build backend image
        run: |
          docker build \
            -t ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:${{ github.sha }} \
            -t ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:latest \
            backend/

      # ─────────────────────────────────────
      # Build — Frontend (Nginx)
      # ─────────────────────────────────────
      - name: Build frontend image
        run: |
          docker build \
            -t ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:${{ github.sha }} \
            -t ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:latest \
            frontend/

      # ─────────────────────────────────────
      # 🔍 Escaneo de seguridad con Trivy
      # (Bloquea el pipeline si hay CRITICAL/HIGH)
      # ─────────────────────────────────────
      - name: Trivy scan backend image
        uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: '${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      - name: Trivy scan frontend image
        uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: '${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      # ─────────────────────────────────────
      # Push imágenes (solo si Trivy pasa)
      # ─────────────────────────────────────
      - name: Push backend image
        run: |
          docker push ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:${{ github.sha }}
          docker push ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-backend:latest

      - name: Push frontend image
        run: |
          docker push ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:${{ github.sha }}
          docker push ${{ env.REGISTRY }}/${{ secrets.PROJECT_ID }}/${{ env.REPO }}/agent-frontend:latest

      # ─────────────────────────────────────
      # Instalar Ansible
      # ─────────────────────────────────────
      - name: Install Ansible
        run: |
          pip install ansible

      # ─────────────────────────────────────
      # Deploy via Ansible → GKE
      # ─────────────────────────────────────
      - name: Deploy to GKE via Ansible
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
          USE_GKE_GCLOUD_AUTH_PLUGIN: "True"
        run: |
          ansible-playbook ansible/deploy-gke.yml \
            --extra-vars "image_tag=${{ github.sha }}"
```

### Resumen de Cambios respecto a la Práctica 1

| Aspecto | Antes (Práctica 1) | Ahora (Securizado) |
|---|---|---|
| Escaneo de seguridad | No existía | Trivy escanea ambas imágenes antes del push |
| Orden Build/Push | Build → Push inmediato | Build → Scan → Push (solo si pasa) |
| Autenticación GCP | `credentials_json: GCP_SA_KEY` | `workload_identity_provider` + `service_account` via OIDC |
| Permisos del workflow | No definidos | `id-token: write` (requerido para OIDC) |
| Paso "Create backend .env" | Sí — escribe API key en `.env` | **Eliminado** — la key va como K8s Secret |
| Secretos en GitHub | 3 + clave JSON | 4 sin clave JSON (WIF provider + SA email) |

---

## Paso 6 — Test Funcional Final

```bash
EXTERNAL_IP=$(kubectl get svc agent-frontend -n ucm-master \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

curl -X POST http://$EXTERNAL_IP/ask \
  -H "Content-Type: application/json" \
  -d '{"input": "What is the price of Bitcoin?"}'
```

El chatbot debe responder normalmente, confirmando que las tres capas de seguridad están activas sin afectar la funcionalidad.

---
