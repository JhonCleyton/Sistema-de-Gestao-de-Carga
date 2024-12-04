import os
import shutil

# Create images directory
images_dir = os.path.join('static', 'images')
os.makedirs(images_dir, exist_ok=True)

# Copy logo
source_logo = 'logo.png'
dest_logo = os.path.join(images_dir, 'logo.png')
shutil.copy2(source_logo, dest_logo)
print(f"Logo copied to {dest_logo}")
