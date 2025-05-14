import pytsk3
import sys

def list_files(img_path):
    img = pytsk3.Img_Info(img_path)
    fs = pytsk3.FS_Info(img)

    def recurse(directory, path="/"):
        for entry in directory:
            if entry.info.name.name in [b".", b".."]:
                continue
            try:
                filepath = path + entry.info.name.name.decode("utf-8")
                print("FILE:", filepath)
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    recurse(entry.as_directory(), filepath + "/")
            except Exception as e:
                print("Error reading entry:", e)

    directory = fs.open_dir("/")
    recurse(directory)

# Use your actual path here
list_files("C:/Users/ASUS/Desktop/ntfs_test.img")
