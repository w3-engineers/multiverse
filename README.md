# Multiverse

This is a websocket server based on socket.io. It's mainly created in pupose of serving as relay server for mesh.

## Production Deployment
Clone repository, run `docker-compose up -d`

Go to multverse code container and run database migrate using `python migrate.py`

Make a reverse proxy for websocket using nginx. Enable SSL using certbot for production.
Add below code under your server config of ngnix.
```
  location / {
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header Host $http_host;
      proxy_set_header X-NginX-Proxy false;

      proxy_pass http://localhost:5000;
      proxy_redirect off;

      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
    }

```
