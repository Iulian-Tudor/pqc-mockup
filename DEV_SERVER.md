# Development Server Setup

## Quick Start

### Option 1: Simple HTTP Server (Recommended for quick testing)

```bash
npm run server
```

This starts a simple Node.js HTTP server on http://localhost:8080 with proper MIME types.

**Advantages:**
- No dependencies beyond Node.js
- Fast startup
- Perfect for ES modules
- Proper application/javascript MIME type

### Option 2: Webpack Dev Server (Full features)

```bash
npm install
npm run dev
```

Starts webpack dev server with hot module replacement and asset bundling.

**Advantages:**
- Hot module replacement (HMR)
- Automatic bundling
- CSS loading
- Babel transpilation

## File Server Features

The simple file server (server.js) includes:

- Correct MIME types for all file types
- Support for ES modules
- CORS headers enabled
- No-cache headers (development)
- Path traversal protection
- Request logging
- Proper 404/500 error handling

## Troubleshooting

### "was blocked because of a disallowed MIME type" Error

This means the server isn't sending application/javascript for .js files.

**Solution:** Use the simple server with `npm run server`

### Module loading errors

Make sure all imports use relative paths:
```javascript
import { App } from './App.js';  // Correct
import { App } from '/App.js';    // Wrong for ES modules
```

### Port already in use

Change the port in server.js (default is 8080):
```javascript
const PORT = 8080;  // Change this
```

## Browser Requirements

- Modern browser with ES module support
- Chrome 61+, Firefox 67+, Safari 10.1+, Edge 79+

## Production Build

```bash
npm run build
```

Creates optimized bundle in dist/ directory.
