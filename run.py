import uvicorn
import argparse
from dotenv import load_dotenv

def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the Coldwire server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with auto-reload and verbose logging")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")


    args = parser.parse_args()
    uvicorn.run(
            "app.main:app", 
            host      = args.host, 
            port      = args.port, 
            reload    = args.debug,
            workers   = 1 if args.debug else 4,
            log_level = "debug" if args.debug else "info"
        )


if __name__ == "__main__":
    main()
