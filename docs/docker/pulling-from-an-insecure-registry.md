# Pulling from an insecure registry

Edit the `daemon.json` file, whose default location is `/etc/docker/daemon.json` on Linux or `C:\ProgramData\docker\config\daemon.json` on Windows Server. If you use Docker Desktop for Mac or Docker Desktop for Windows, click the Docker icon, choose **Preferences**, and choose **Docker Engine**.

```
{
  "insecure-registries" : ["myregistrydomain.com:5000"]
}
```

Source: [https://docs.docker.com/registry/insecure/](https://docs.docker.com/registry/insecure/)
