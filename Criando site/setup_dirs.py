import os

# Create necessary directories
dirs = [
    'static',
    'static/css',
    'static/js',
    'templates'
]

base_dir = os.path.dirname(os.path.abspath(__file__))
for dir_path in dirs:
    full_path = os.path.join(base_dir, dir_path)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
        print(f"Created directory: {full_path}")
