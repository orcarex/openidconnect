# Django OpenID Connect Provider

A Django-based OpenID Connect (OIDC) and OAuth2 provider implementation with comprehensive authentication and authorization features.

## Features

- 🔐 **OAuth2 Provider**: Full OAuth2 authorization server implementation
- 🆔 **OpenID Connect**: OIDC provider with JWT token support
- 🔑 **Multiple Authentication**: Support for various authentication methods
- 🛡️ **Security**: Built-in security features and best practices
- 🔧 **REST API**: RESTful API endpoints with authentication
- 📱 **WebSocket Support**: Real-time communication capabilities
- 🌍 **Environment Configuration**: Flexible environment-based configuration

## Tech Stack

- **Framework**: Django 5.2.4
- **Authentication**: django-oauth-toolkit, django-allauth, djoser
- **API**: Django REST Framework 3.16.0
- **JWT**: djangorestframework-simplejwt 5.5.1
- **Environment**: django-environ 0.12.0
- **WebSockets**: websockets 15.0.1

## Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/orcarex/openidconnect.git
   cd openidconnect
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Configuration**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env file with your settings
   nano .env
   ```

4. **Database Setup**
   ```bash
   cd odic
   python manage.py migrate
   ```

5. **Create Superuser** (Optional)
   ```bash
   python manage.py createsuperuser
   ```

6. **Run the Development Server**
   ```bash
   python manage.py runserver
   ```

The application will be available at `http://localhost:8000`

### OAuth2 Application Setup

To use the OAuth2 functionality, you need to create an OAuth2 application:

1. **Access Django Admin**
   ```bash
   # Create superuser if not already done
   python manage.py createsuperuser
   ```

2. **Create OAuth2 Application**
   - Go to `http://localhost:8000/admin/`
   - Navigate to "OAuth2 Provider" → "Applications"
   - Click "Add Application"
   - Set:
     - **Name**: Your app name
     - **Client type**: Confidential
     - **Authorization grant type**: Authorization code
     - **Redirect URIs**: Your callback URL (e.g., `http://localhost:3000/callback`)

3. **Note your credentials**
   - **Client ID**: Will be generated automatically
   - **Client Secret**: Will be generated automatically
   - Use these in your OAuth2 flow

## Environment Configuration

The project uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

```env
# Django Settings
DEBUG=True
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///db.sqlite3

# Security Settings
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
SECURE_SSL_REDIRECT=False
SECURE_HSTS_SECONDS=0
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `True` |
| `SECRET_KEY` | Django secret key | Auto-generated |
| `DATABASE_URL` | Database connection URL | `sqlite:///db.sqlite3` |
| `ALLOWED_HOSTS` | Comma-separated allowed hosts | `localhost,127.0.0.1,0.0.0.0` |

## Project Structure

```
openidconnect/
├── odic/                          # Main Django project
│   ├── custom_protected_resource/ # Custom OAuth2 resource protection
│   ├── odic/                      # Django settings and configuration
│   │   ├── settings.py           # Main settings file
│   │   ├── urls.py               # URL routing
│   │   └── wsgi.py               # WSGI configuration
│   ├── manage.py                 # Django management script
│   ├── websocket_client_example.py # WebSocket client example
│   └── websocket_server_example.py # WebSocket server example
├── requirements.txt              # Python dependencies
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
└── README.md                    # This file
```

## API Endpoints

The application provides several API endpoints:

### OAuth2 Endpoints
- `/o/authorize/` - OAuth2 authorization endpoint
- `/o/token/` - OAuth2 token endpoint
- `/o/revoke_token/` - Token revocation endpoint
- `/o/introspect/` - Token introspection endpoint

### OpenID Connect Endpoints
- `/userinfo/` - OIDC UserInfo endpoint (protected resource)

### Admin Interface
- `/admin/` - Django admin interface

### Additional Authentication Endpoints (Available but commented out)
- `/auth/` - dj-rest-auth endpoints
- `/auth/registration/` - User registration endpoints
- `/auth/` - Djoser authentication endpoints

## Usage Examples

### OAuth2 Authorization Flow

1. **Authorization Request**
   ```
   GET /o/authorize/?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=read
   ```

2. **Token Exchange**
   ```bash
   curl -X POST http://localhost:8000/o/token/ \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_CODE&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&redirect_uri=YOUR_REDIRECT_URI"
   ```

### API Access with Token

```bash
# Access UserInfo endpoint (OIDC)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/userinfo/

# Response example:
# {
#   "sub": 1,
#   "name": "John Doe",
#   "email": "john@example.com"
# }
```

## WebSocket Support

The project includes WebSocket examples for real-time communication:

- `websocket_server_example.py` - WebSocket server implementation
- `websocket_client_example.py` - WebSocket client example

## Development

### Running Tests

```bash
cd odic
python manage.py test
```

### Code Quality Checks

```bash
# Django system check
python manage.py check

# Security check
python manage.py check --deploy
```

### Database Migrations

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

## Production Deployment

For production deployment, make sure to:

1. **Set Environment Variables**
   ```env
   DEBUG=False
   SECRET_KEY=your-production-secret-key
   ALLOWED_HOSTS=yourdomain.com
   DATABASE_URL=postgresql://user:pass@localhost/dbname
   SECURE_SSL_REDIRECT=True
   SECURE_HSTS_SECONDS=31536000
   SESSION_COOKIE_SECURE=True
   CSRF_COOKIE_SECURE=True
   ```

2. **Use Production Database**
   - PostgreSQL recommended
   - Configure DATABASE_URL accordingly

3. **Static Files**
   ```bash
   python manage.py collectstatic
   ```

4. **Use Production WSGI Server**
   - Gunicorn, uWSGI, or similar
   - Configure reverse proxy (Nginx)

## Dependencies

### Core Dependencies
- **Django 5.2.4** - Web framework
- **django-oauth-toolkit 3.0.1** - OAuth2 provider
- **djangorestframework 3.16.0** - REST API framework
- **django-allauth 65.10.0** - Authentication system

### Full Dependency List
See `requirements.txt` for complete list with exact versions.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

- Keep your `SECRET_KEY` secure and never commit it to version control
- Use HTTPS in production
- Regularly update dependencies
- Follow Django security best practices

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the Django and OAuth2 documentation
- Review the project's dependency documentation

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Make sure all dependencies are installed
   pip install -r requirements.txt
   ```

2. **Database Issues**
   ```bash
   # Reset database if needed
   rm odic/db.sqlite3
   python manage.py migrate
   python manage.py createsuperuser
   ```

3. **Environment Variables Not Loading**
   - Ensure `.env` file exists in project root
   - Check `.env.example` for required variables
   - Verify no syntax errors in `.env` file

4. **Port Already in Use**
   ```bash
   # Use different port
   python manage.py runserver 8001
   ```

5. **Static Files Issues**
   ```bash
   python manage.py collectstatic
   ```

## Changelog

### Recent Updates (2024)
- **Major Dependency Update**: All packages updated to latest stable versions
- **Django 5.2.4**: Upgraded from 4.2.1 with full compatibility
- **Environment Configuration**: Added proper django-environ integration
- **Security Improvements**: Enhanced environment variable management
- **Documentation**: Comprehensive README and dependency documentation

See `DEPENDENCY_UPDATE_SUMMARY.md` for detailed changes and version history.

---

**Note**: This is a development setup. For production use, please review and implement appropriate security measures, use a production database, and configure proper hosting infrastructure.