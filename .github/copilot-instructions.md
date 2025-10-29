# PMUL REST Adapter Server - AI Assistant Instructions

## Project Overview
This is a FastAPI-based REST adapter server that implements BeyondTrust Entitle integration endpoints. The server provides mock data and routing capabilities for testing Entitle integrations.

## Key Components

### Core Architecture
- `main.py` - FastAPI application entry point that includes the entitle router
- `routers/entitle.py` - Primary router implementing Entitle integration endpoints
- `constants.py` - Mock data definitions and configuration settings
- `models.py` - Pydantic models for request validation
- `utils/permissions.py` - Permission handling utilities
- `pmulrest.py` - the PMUL REST adapter interface module

### Data Model
The mock data scenario in `constants.py` represents:
- Three user accounts (John, Jane, Hugh)
- Three groups with member/admin/owner roles
- One repository with maintainer/admin roles
- Permission inheritance (e.g., membership in "Admins" group grants repo admin access)
The file `routers/entitleopenapi.yaml` defines the OpenAPI specification for the Entitle endpoints and data structures.

## Development Workflows

### Setup & Running
```bash
# Create and activate virtual environment (recommended)
python -m venv rest_venv
source rest_venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py --host 0.0.0.0 --port 5000
```

### API Endpoints
Core endpoints implemented in `routers/entitle.py`:
- GET `/get_assets` - List available assets
- GET `/get_actors` - List user accounts
- GET `/get_asset_permissions/{asset_id}` - Get permissions for specific asset
- GET `/get_all_permissions` - Get all permission mappings
- POST `/give_access` - Grant access (mock implementation)
- POST `/revoke_access` - Revoke access (mock implementation)
- POST `/check_config` - Validate configuration
- POST `/create_actor` - Create new actor
- POST `/delete_actor` - Delete existing actor

## Project Patterns

### Request Validation
- Use Pydantic models in `models.py` for request body validation
- Example: `AccessRequestBody` validates asset, actor_identifier and role_code fields

### Logging
- Use the project logger from `logger.py` for consistent logging
- Example: `logger.debug(f'get_asset_permissions called with asset_id={asset_id}')`

### Mock Data Structure
- Asset types: 'group' and 'repo'
- Role hierarchies defined in `GROUP_ROLE_OPTIONS` and `REPO_ROLE_OPTIONS`
- Permissions mapped in `ACTOR_PERMISSIONS` and `ASSET_PERMISSIONS`