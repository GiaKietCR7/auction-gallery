# Deploy Auction Gallery (Render)

1. Commit/push code lên GitHub (giữ `server.js` và thư mục `views/`, `public/`...).
2. Thêm các file này vào repo (từ bundle này):
   - `package.json`
   - `.gitignore`
   - `.env.example`
   - `render.yaml`
3. Vào render.com → New → Blueprint → chọn repo.
4. Trong Environment, set biến:
   - `SESSION_SECRET` (bất kỳ chuỗi mạnh)
   - `ADMIN_KEY` (khóa admin của bạn)
5. Deploy. Render sẽ cấp domain HTTPS.

## Lưu ý dữ liệu
- SQLite và sessions nằm trong `data/` → đã mount Persistent Disk trong `render.yaml`.
- Ảnh sản phẩm nằm trong `uploads/`. Nếu muốn giữ sau mỗi redeploy, bật thêm `additionalDisks` trong `render.yaml` và map `uploads/`.

## Chạy local
```
npm install
npm run start
# http://localhost:3000
```
