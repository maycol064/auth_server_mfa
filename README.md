# Django API - README

## Descripción
Esta API ha sido desarrollada con Django y Django REST Framework (DRF). Proporciona funcionalidades de autenticación con MFA
## Requisitos
Antes de instalar y ejecutar la API, asegúrate de tener los siguientes requisitos:

- Python 3.8+
- Django 4+
- Django REST Framework

## Instalación
Sigue estos pasos para instalar y configurar la API:

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/maycol064/auth_server_mfa
   cd tu_repositorio
   ```

2. Crear un entorno virtual y activarlo:
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```

3. Instalar las dependencias

5. Aplicar migraciones:
   ```bash
   python manage.py migrate
   ```

7. Ejecutar el servidor:
   ```bash
   python manage.py runserver
   ```

## Endpoints Principales
La API incluye los siguientes endpoints principales:

- **Autenticación**
  - `POST /auth/login/` → Iniciar sesión
  - `POST /auth/logout/` → Cerrar sesión
  - `POST /auth/register/` → Registrar usuario
  
- **Verificación MFA**
  - `POST /auth/verify_mfa/` → Verificar token
  - `POST /auth/initiate_mfa_setup/` → Inicializar la configuración
  - `POST /auth/verify_and_enable_mfa/` → Verificacar token por primerq vez y habilitar mfa
  - `POST /auth/disable_mfa/` → Deshabilitar mfa


## Variables de Entorno
Crea un archivo `.env` en la raíz del proyecto y define las variables necesarias:
```
```

## Pruebas
Ejecuta los tests con:
```bash
python manage.py test
```

## Despliegue
Para desplegar en producción, sigue estos pasos:
1. Configura `DEBUG=False` en `settings.py`.
2. Utiliza EC2 para el despliegue de la API