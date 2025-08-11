# Admin Toolkit

[![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![pnpm](https://img.shields.io/badge/pnpm-F69220?style=for-the-badge&logo=pnpm&logoColor=white)](https://pnpm.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

A powerful, schema-driven web-based toolkit for systems engineers, network engineers, and DevOps practitioners. This application provides a unified interface for a vast array of command-line tools, with a strong emphasis on safety, automation, and end-to-end workflow management, especially for SSL/TLS certificates.

## Key Features

- **Comprehensive Tooling**: Wraps a wide range of common CLI tools for Linux administration, networking, container management, and cloud interaction.
- **Schema-Driven Actions**: Every command is defined by a strict JSON schema, which enables auto-generated UI forms, parameter validation, and safe command rendering.
- **Three Execution Modes**: Designed to be flexible with client-side WASM execution for safe tools, a remote runner for protected commands, and an optional local agent for full on-prem access.
- **End-to-End SSL/TLS Management**: A dedicated suite of tools to handle every aspect of the PKI lifecycle: key/CSR generation, certificate inspection, chain validation, format conversion (PEM, PKCS#12, JKS), and OCSP checks.

## Tech Stack

- **Frontend**: Next.js, React, TypeScript, Tailwind CSS, shadcn/ui, Zustand, xterm.js.
- **Backend**: FastAPI (Python 3.11).
- **Database**: PostgreSQL.
- **Containerization**: Docker & Docker Compose for a portable development environment.
- **Monorepo Management**: pnpm workspaces to manage shared and separate packages efficiently.
- **Client-side Tools**: WebAssembly (WASM) versions of `jq`, `yq`, `ripgrep`, and more for fast, safe, in-browser operations.

## Project Structure

This project is a monorepo managed by pnpm.

```
.
├── apps/
│   ├── backend/      # FastAPI application, Dockerfile, and Python dependencies
│   └── frontend/     # Next.js web application
├── packages/
│   └── schemas/      # JSON schemas for all supported actions
├── docker-compose.yml # Orchestrates the backend and database services
├── pnpm-workspace.yaml # Defines the monorepo workspaces
└── README.md
```

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [pnpm](https://pnpm.io/installation) (v8+)
- [Docker](https://www.docker.com/get-started) and Docker Compose
- [Python](https://www.python.org/downloads/) (v3.11+)

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-name>
    ```

2.  **Install frontend dependencies:**
    The `pnpm install` command will read the workspace configuration and install dependencies for all apps and packages.
    ```bash
    pnpm install
    ```

### Running the Application

The application is designed to run with Docker Compose, which orchestrates the backend server and the PostgreSQL database. The frontend development server is run directly via pnpm.

1.  **Start the backend and database:**
    ```bash
    sudo docker compose up --build -d
    ```
    The `-d` flag runs the services in detached mode. The backend API will be available at `http://localhost:8000`.

2.  **Start the frontend development server:**
    ```bash
    pnpm --filter frontend dev
    ```
    The frontend application will be available at `http://localhost:3000`.
