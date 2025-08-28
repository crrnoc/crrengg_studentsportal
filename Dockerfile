# ========================
# 1. Base image
# ========================
FROM node:20

# ========================
# 2. Set working directory
# ========================
WORKDIR /app

# ========================
# 3. Install Python (for PDF parsing) and venv tools
# ========================
RUN apt-get update && apt-get install -y python3 python3-venv python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ========================
# 4. Copy Node package files and install dependencies
# ========================
COPY package*.json ./
RUN npm install --production

# ========================
# 5. Copy the rest of the project
# ========================
COPY . .

# ========================
# 6. Setup Python virtual environment and install requirements at build-time
# ========================
RUN python3 -m venv .venv && \
    /bin/bash -c "source .venv/bin/activate && pip install --no-cache-dir -r requirements.txt"

# ========================
# 7. Ensure uploads + public folders exist
# ========================
RUN mkdir -p /app/uploads /app/public

# ========================
# 8. Make start.sh executable
# ========================
RUN chmod +x start.sh

# ========================
# 9. Set environment variables
# ========================
ENV NODE_ENV=production
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# ========================
# 10. Expose port
# ========================
EXPOSE 8080

# ========================
# 11. Start the app using start.sh
# ========================
CMD ["./start.sh"]
