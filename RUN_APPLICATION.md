# Run The Complete Application

This guide uses Python 3.13 at:
`C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe`

## 1) Install dependencies

```powershell
cd C:\Users\CHAKRI\Desktop\Major
C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe -m pip install -r requirements.txt
```

## 2) Create JWT RSA keys

```powershell
cd C:\Users\CHAKRI\Desktop\Major
C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe scripts\generate_rsa_keys.py
```

This creates:
- `C:\Users\CHAKRI\Desktop\Major\keys\private.pem`
- `C:\Users\CHAKRI\Desktop\Major\keys\public.pem`

## 3) Create environment file

```powershell
cd C:\Users\CHAKRI\Desktop\Major
Copy-Item .env.example .env -Force
```

Set these in `.env`:
- `JWT_PRIVATE_KEY_PATH=./keys/private.pem`
- `JWT_PUBLIC_KEY_PATH=./keys/public.pem`
- `ADMIN_API_KEY=change-me` (set your own secret)

## 4) (Optional) Train/update reputation model bundle

```powershell
cd C:\Users\CHAKRI\Desktop\Major
C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe scripts\train_reputation_model.py
```

Output model:
- `C:\Users\CHAKRI\Desktop\Major\models\reputation_model_bundle.joblib`

## 5) Run tests

```powershell
cd C:\Users\CHAKRI\Desktop\Major
C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe -m pytest -q
```

## 6) Start the app

```powershell
cd C:\Users\CHAKRI\Desktop\Major
C:\Users\CHAKRI\AppData\Local\Programs\Python\Python313\python.exe run.py
```

App URLs:
- Frontend dashboard: `http://127.0.0.1:5000/`
- Auth APIs: `/auth/*`
- Protected APIs: `/api/*`
- Admin APIs: `/admin/*` (requires `X-Admin-Key`)
