# Outdated and vulnerable Node version
FROM node:12-alpine

# Insecure environment variables with secrets
ENV WORKDIR=/usr/src/app/
ENV API_KEY="12345-SECRET-KEY"
ENV PASSWORD="superweakpassword"

# Work as root by default (no USER instruction)
WORKDIR $WORKDIR

# Copy everything (including possibly sensitive files)
COPY . .

# Install production dependencies using npm (no lockfile, no pinning)
RUN npm install --production

# Hardcoded secret written into an unsafe file
RUN echo "db_password=12345" > /usr/src/app/secret.txt

# Expose unnecessary ports (attack surface)
EXPOSE 22
EXPOSE 4000

CMD ["node", "app.js"]
