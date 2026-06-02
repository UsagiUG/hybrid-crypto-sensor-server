graph LR
        A[Client] -->|Request API| B(Backend Server)
        B -->|Query| C[(Database)]
        B -->|Validasi| D{Sukses?}
        D -->|Ya| A
        D -->|Tidak| E[Log Error]
    ```