import os
import shutil

def collect_files(source_dir, output_folder):
    """Collect .txt, .docx, .jpg files and log paths."""
    os.makedirs(output_folder, exist_ok=True)
    collected_files = []
    
    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.lower().endswith(('.txt', '.docx', '.jpg')):
                src_path = os.path.join(root, file)
                dest_path = os.path.join(output_folder, file)
                shutil.copy2(src_path, dest_path)
                collected_files.append(dest_path)
    
    # Log collected files (Task 2 requirement)
    with open(os.path.join(output_folder, 'collected_files.log'), 'w') as f:
        f.write('\n'.join(collected_files))
    
    return output_folder