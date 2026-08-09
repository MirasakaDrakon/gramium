package main

import (
    "flag"
    "os"
    "fmt"
)

func main() {
    cliMode := flag.Bool("cli", false, "Run in CLI mode")
    proxy := flag.String("proxy", "", "Proxy URL (e.g., socks5://127.0.0.1:1080, http://proxy.example.com:8080)")
    flag.Parse()

    if *cliMode || len(os.Args) > 1 && os.Args[1] == "-cli" {
        RunCLI(*proxy)
    } else {
        // GUI DISABLED!!!
        fmt.Println("GUI mode not implemented. Use -cli flag.")
        //RunGUI()
    }
}