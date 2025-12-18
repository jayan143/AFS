# test_imports.py
try:
    import routeros_api
    print(f"routeros_api version: {routeros_api.__version__}")
except ImportError:
    print("routeros_api not found")
    print("Try: pip install routeros-api")
    
try:
    import flask
    print(f"Flask version: {flask.__version__}")
except ImportError:
    print("Flask not found")