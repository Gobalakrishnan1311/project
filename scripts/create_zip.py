import os
import zipfile
import sys

def create_project_zip(output_path="/tmp/webbug-hunter-source.zip"):
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Directories to include
        include_dirs = ['src', 'server', 'backend']
        for d in include_dirs:
            if os.path.exists(d):
                for root, dirs, files in os.walk(d):
                    # Skip __pycache__ or temporary files
                    dirs[:] = [dir_name for dir_name in dirs if dir_name not in ('__pycache__', '.pytest_cache')]
                    for f in files:
                        if f.endswith(('.pyc', '.pyo')):
                            continue
                        full_path = os.path.join(root, f)
                        rel_path = os.path.relpath(full_path, root_dir)
                        zipf.write(full_path, rel_path)

        # Root files to include
        include_files = [
            'package.json',
            'package-lock.json',
            'tsconfig.json',
            'vite.config.ts',
            'index.html',
            'README.md',
            '.env.example',
            '.gitignore',
            'Dockerfile',
            'docker-compose.yml',
            'metadata.json'
        ]

        for f in include_files:
            if os.path.exists(f):
                zipf.write(f, f)

    print(f"Created {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/webbug-hunter-source.zip"
    create_project_zip(out)
