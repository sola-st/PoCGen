{
    "targets": [
        {
            "target_name": "function_location",
            "sources": ["function_location.cc"],
            "include_dirs": ["<!(node -e \"require('nan')\")"],
        }
    ]
}
