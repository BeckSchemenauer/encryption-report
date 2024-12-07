import os


# Create files of specific sizes in MB
def create_file(filename, size_mb):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_mb * 1024 * 1024))


create_file("test_1MB.txt", 1)
create_file("test_10MB.txt", 10)
create_file("test_100MB.txt", 100)
create_file("test_1000MB.txt", 1000)
