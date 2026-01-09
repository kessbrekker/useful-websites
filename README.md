# Website Directory Platform

A modern, minimalist website directory built with Vanilla HTML/JS, running on Cloudflare Pages (Frontend) and Cloudflare Workers + D1 (Backend).

## Project Structure

- `public/`: Static Frontend Assets (HTML, CSS, JS).
- `functions/`: Backend Cloudflare Workers.
- `schema.sql`: Database schema for Cloudflare D1.

## Local Development

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Setup Local Database**
   ```bash
   npx wrangler d1 execute DB --local --file=./schema.sql
   ```

3. **Run Development Server**
   ```bash
   npm run dev
   ```
   Open [http://localhost:8788](http://localhost:8788).

## Deployment (Cloudflare Pages)

### Configuration
1. Create a new Cloudflare Pages project pointing to this repository.
2. **Build Settings**:
   - **Framework Preset**: None / Custom
   - **Build Command**: `npm run build`
   - **Build Output Directory**: `public`
3. **Environment Variables** (Settings > Environment Variables):
   - `JWT_SECRET`: A random string for signing tokens.
   - `ADMIN_SECRET_TOKEN`: A token for the specific "Add with Token" feature.
4. **Database Binding** (Settings > Functions):
   - Create a D1 Database.
   - Bind it to the variable name: `DB`.

### Note on "npm run deploy"
The `npm run deploy` script in `package.json` is for **manual** direct uploads from your local terminal. **Do not** use this as your Build Command in Cloudflare Pages, as it requires authentication credentials that are not present in the CI environment.