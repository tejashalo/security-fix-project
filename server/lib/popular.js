'use strict';
/** Popular package names — used to spot look-alike (typo-squatted) names. */
const NPM = `react react-dom next vue nuxt svelte @sveltejs/kit angular @angular/core express fastify koa hono axios lodash underscore
moment dayjs date-fns uuid nanoid dotenv cors helmet morgan body-parser cookie-parser express-session jsonwebtoken bcrypt bcryptjs argon2
mongoose mongodb pg mysql mysql2 sqlite3 better-sqlite3 sequelize typeorm prisma @prisma/client drizzle-orm knex redis ioredis
socket.io socket.io-client ws graphql apollo-server @apollo/client zod joi yup express-validator validator multer sharp jimp
nodemailer stripe @stripe/stripe-js openai @anthropic-ai/sdk @google/generative-ai @google/genai langchain ai firebase firebase-admin
@supabase/supabase-js @clerk/nextjs next-auth passport passport-local passport-jwt tailwindcss postcss autoprefixer sass less
typescript ts-node tsx nodemon concurrently cross-env eslint prettier jest vitest mocha chai supertest webpack vite rollup esbuild
babel-core @babel/core parcel react-router react-router-dom redux @reduxjs/toolkit zustand jotai recoil mobx swr @tanstack/react-query
styled-components @emotion/react @mui/material antd chakra-ui @chakra-ui/react framer-motion three d3 chart.js recharts
react-native expo react-native-web @react-navigation/native axios-retry got node-fetch cheerio puppeteer playwright commander yargs
chalk ora inquirer debug winston pino bunyan uuidv4 crypto-js node-cron bull bullmq agenda aws-sdk @aws-sdk/client-s3 cloudinary
twilio @sendgrid/mail resend mailgun.js formidable busboy express-fileupload compression http-proxy-middleware rimraf glob fs-extra
classnames clsx lucide-react react-icons @headlessui/react @radix-ui/react-dialog react-hook-form formik i18next react-i18next
marked markdown-it dompurify isomorphic-dompurify xss sanitize-html qs query-string jquery bootstrap electron electron-builder`.split(/\s+/).filter(Boolean);

const PYPI = `flask django fastapi uvicorn gunicorn requests httpx aiohttp sqlalchemy psycopg2 psycopg2-binary pymongo redis celery pydantic
numpy pandas scipy scikit-learn matplotlib seaborn tensorflow torch torchvision transformers openai anthropic langchain python-dotenv
pillow boto3 stripe jinja2 werkzeug flask-cors flask-login flask-sqlalchemy flask-jwt-extended djangorestframework django-cors-headers
pyjwt bcrypt passlib cryptography beautifulsoup4 lxml selenium pytest black flake8 mypy click typer rich tqdm pyyaml marshmallow alembic`.split(/\s+/).filter(Boolean);

module.exports = { NPM, PYPI };
