- Please insert these extra lines to the configuration template of the worker nodes just like in `cluster.template.yaml` file.
```yaml
initConfiguration:
      extraWriteFiles:
      - path: /tmp/script.py
        owner: root:root
        permissions: "0777"
        content: |
          {{CONTENT}}
      postRunCommands:
      - 
      - chmod +x /tmp/script.py
      - export $(snap run --shell microk8s -c 'env' | grep 'SNAP' | xargs) && python3 /tmp/script.py
```

- Run the following bash script to populate the hardening python script into your cluster manifests:
```bash
./generate.sh <YOUR_CLUSTER_FILE>
```
- Use the generated `cluster.yaml` to deploy your workload cluster

