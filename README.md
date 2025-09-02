# UserAdminApi (.NET 9 Minimal API)

User administration API with:
- Swagger UI
- Optional AES-256 encryption of PII (feature flag `FeatureManagement:EncryptUserData`)
- Pluggable storage: JSON file (default) or MongoDB (via `STORAGE_PROVIDER` env var)

# Purpose 
Simple Rest API to try multiple things
- CI/CD
- Code analysis
- Docker compose
- Docker volume
- K8S deployment
  - config map
  - secrets
  - services
  - PV
  - PVC
- Use distroless to minimalminimize image size, current size is 412 MB



## Quick start

```bash
# prerequisites: .NET 9 SDK
dotnet restore
dotnet run
# Open http://localhost:5199/swagger
```

## Configure

- **Storage selection** (env var):
  - `STORAGE_PROVIDER=json` (default) uses `JsonStorage:Path` (default `App_Data/users.json`)
  - `STORAGE_PROVIDER=mongodb` uses `MONGODB_URI`, `MONGODB_DB`, `MONGODB_COLLECTION`

- **Encryption feature flag**:
  - `FeatureManagement:EncryptUserData` (bool) controls whether Email/FullName are stored encrypted.
  - Provide `ENCRYPTION_KEY_BASE64` (32-byte key) and `ENCRYPTION_IV_BASE64` (16-byte IV) for consistent encryption.
  - If enabled but no key/iv are provided, a random, process-local key will be generated (dev only).

## API
CRUD under `/api/users`. See Swagger for schema.


## helm and k8s deployment

helm install useradminapi ./Helm --create-namespace
 helm list
 helm uninstall useradminapi -n default
 helm releases
 kt get pods -A
 helm list -a -A -o table
 helm upgrade useradminapi ./Helm --set image.tag=2.0
 helm history useradminapi
helm get values useradminapi --all   ---> list all values of deployed chart
helm diff revision useradminapi 1 2 --> difference between two revisions

# Mongo DB

```bash
docker run -d --name mongodb -p 27017:27017 -v mongodb:/data/db -e MONGO_INITDB_ROOT_USERNAME=mongoadmin -e MONGO_INITDB_ROOT_PASSWORD=password1234 mongo:noble
```

Build an image and pass mongodb uri, user account and credentials as env variable, 
Note: Remember to use host.docker.internal as mongo db container is running seperately, docker wont be able to find using localhost.

```bash
export MONGODB_URI="mongodb://myUser:myPassword@localhost:27017/UserAdminDb?authSource=admin"

"STORAGE_PROVIDER=mongodb",
			"MONGODB_URI=mongodb://mongoadmin:password1234@host.docker.internal:27017/UserAdminDb?authSource=admin",


```
use `__` to map nested variable
ex: Logging__LogLevel__Default=Debug
```json
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  ```

# Run UserAdminAPI with mongoDB
```shell
docker run -d --name useradmiapi -p 9090:8080 -e Logging__LogLevel__Default=debug \
-e STORAGE_PROVIDER=mongodb \
-e MONGODB_URI="mongodb://mongoadmin:password1234@host.docker.internal:27017/UserAdminDb?authSource=admin" \
-t bhoobal/useradmiapi:2.0

docker run -d --name useradmiapi -p 9090:8080 -e Logging__LogLevel__Default=debug \
-e STORAGE_PROVIDER=mongodb \
-e MONGODB_URI="mongodb://mongoadmin:password1234@host.docker.internal:27017/UserAdminDb?authSource=admin" -e Logging__LogLevel__Microsoft.AspNetCore=debug \
-t bhoobal/useradmiapi:2.0
```

