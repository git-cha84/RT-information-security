#!/bin/bash
set -e

# 1. Установка зависимостей
echo "=== УСТАНОВКА ЗАВИСИМОСТЕЙ ==="
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r) gcc-12 cmake

# 2. Создание структуры проекта
echo -e "\n=== СОЗДАНИЕ ПРОЕКТА ==="
mkdir -p process_info_project
cd process_info_project

# 3. Модуль ядра (process_info.c)
echo -e "\n=== СОЗДАНИЕ МОДУЛЯ ЯДРА ==="
cat > process_info.c << 'EOL'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define MODULE_NAME "process_info"

static struct kobject *proc_kobj;

struct proc_data {
    pid_t pid;
    char *user_id;
    char *exe_path;
    char *cmdline;
};

static struct proc_data *data;

static ssize_t pid_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", data->pid);
}

static ssize_t user_id_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", data->user_id);
}

static ssize_t exe_path_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", data->exe_path);
}

static ssize_t cmdline_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", data->cmdline);
}

static ssize_t pid_store(struct kobject *kobj, struct kobj_attribute *attr,
                         const char *buf, size_t count)
{
    int ret;
    pid_t pid;
    struct task_struct *task;
    struct mm_struct *mm;
    char *path_buf;
    char *cmdline_buf;

    ret = kstrtoint(buf, 10, &pid);
    if (ret < 0)
        return ret;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }

    if (data) {
        kfree(data->user_id);
        kfree(data->exe_path);
        kfree(data->cmdline);
    } else {
        data = kmalloc(sizeof(struct proc_data), GFP_KERNEL);
        if (!data) {
            rcu_read_unlock();
            return -ENOMEM;
        }
    }

    data->pid = pid;
    data->user_id = kasprintf(GFP_KERNEL, "%u", __kuid_val(task->cred->uid));
    if (!data->user_id) {
        rcu_read_unlock();
        kfree(data);
        data = NULL;
        return -ENOMEM;
    }

    mm = get_task_mm(task);
    if (mm) {
        path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_buf) {
            char *pathname = d_path(&mm->exe_file->f_path, path_buf, PATH_MAX);
            if (!IS_ERR(pathname)) {
                data->exe_path = kstrdup(pathname, GFP_KERNEL);
            }
            kfree(path_buf);
        }
        mmput(mm);
    }

    if (!data->exe_path) {
        data->exe_path = kstrdup("[unknown]", GFP_KERNEL);
    }

    cmdline_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (cmdline_buf) {
        int len;
        mm = get_task_mm(task);
        if (mm) {
            len = access_process_vm(task, mm->arg_start, cmdline_buf,
                                  mm->arg_end - mm->arg_start, FOLL_FORCE);
            if (len > 0) {
                int i;
                for (i = 0; i < len; i++) {
                    if (cmdline_buf[i] == '\0')
                        cmdline_buf[i] = ' ';
                }
                cmdline_buf[len-1] = '\0';
                data->cmdline = kstrdup(cmdline_buf, GFP_KERNEL);
            }
            mmput(mm);
        }
        kfree(cmdline_buf);
    }

    if (!data->cmdline) {
        data->cmdline = kstrdup("[unknown]", GFP_KERNEL);
    }

    rcu_read_unlock();
    return count;
}

static struct kobj_attribute pid_attribute =
    __ATTR(pid, 0664, pid_show, pid_store);
static struct kobj_attribute user_id_attribute =
    __ATTR(user_id, 0444, user_id_show, NULL);
static struct kobj_attribute exe_path_attribute =
    __ATTR(exe_path, 0444, exe_path_show, NULL);
static struct kobj_attribute cmdline_attribute =
    __ATTR(cmdline, 0444, cmdline_show, NULL);

static struct attribute *attrs[] = {
    &pid_attribute.attr,
    &user_id_attribute.attr,
    &exe_path_attribute.attr,
    &cmdline_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

static int __init process_info_init(void)
{
    int ret;

    proc_kobj = kobject_create_and_add("process_info", kernel_kobj);
    if (!proc_kobj)
        return -ENOMEM;

    ret = sysfs_create_group(proc_kobj, &attr_group);
    if (ret)
        kobject_put(proc_kobj);

    return ret;
}

static void __exit process_info_exit(void)
{
    if (data) {
        kfree(data->user_id);
        kfree(data->exe_path);
        kfree(data->cmdline);
        kfree(data);
    }
    kobject_put(proc_kobj);
}

module_init(process_info_init);
module_exit(process_info_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Process information module");
EOL

# 4. Makefile для модуля ядра
echo -e "\n=== СОЗДАНИЕ MAKEFILE ==="
cat > Makefile << 'EOL'
obj-m := process_info.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC := gcc-12

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
EOL

# 5. Прикладное приложение (process_info_app.c)
echo -e "\n=== СОЗДАНИЕ ПРИЛОЖЕНИЯ ==="
cat > process_info_app.c << 'EOL'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define SYSFS_PATH "/sys/kernel/process_info/"

void read_sysfs_file(const char *attribute, char *buffer, size_t size) {
    char path[256];
    int fd;
    ssize_t bytes_read;

    snprintf(path, sizeof(path), "%s%s", SYSFS_PATH, attribute);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open sysfs file");
        exit(EXIT_FAILURE);
    }

    bytes_read = read(fd, buffer, size - 1);
    if (bytes_read < 0) {
        perror("Failed to read sysfs file");
        close(fd);
        exit(EXIT_FAILURE);
    }

    buffer[bytes_read] = '\0';

    if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
        buffer[bytes_read - 1] = '\0';
    }

    close(fd);
}

void write_sysfs_file(const char *attribute, const char *value) {
    char path[256];
    int fd;
    ssize_t bytes_written;

    snprintf(path, sizeof(path), "%s%s", SYSFS_PATH, attribute);

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open sysfs file for writing");
        exit(EXIT_FAILURE);
    }

    bytes_written = write(fd, value, strlen(value));
    if (bytes_written < 0) {
        perror("Failed to write to sysfs file");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

void print_process_info(pid_t pid) {
    char pid_str[16];
    char user_id[64];
    char exe_path[1024];
    char cmdline[4096];

    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    write_sysfs_file("pid", pid_str);

    read_sysfs_file("user_id", user_id, sizeof(user_id));
    read_sysfs_file("exe_path", exe_path, sizeof(exe_path));
    read_sysfs_file("cmdline", cmdline, sizeof(cmdline));

    printf("Process ID: %d\n", pid);
    printf("User ID: %s\n", user_id);
    printf("Executable path: %s\n", exe_path);
    printf("Command line: %s\n", cmdline);
    printf("----------------------------------------\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid1> [pid2] ... [pidN]\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        pid_t pid = atoi(argv[i]);
        if (pid <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", argv[i]);
            continue;
        }

        print_process_info(pid);
    }

    return EXIT_SUCCESS;
}
EOL

# 6. CMakeLists.txt
echo -e "\n=== СОЗДАНИЕ CMAKELISTS.TXT ==="
cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.10)
project(process_info)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER /usr/bin/gcc-12)

add_executable(process_info_app process_info_app.c)
EOL

# 7. Скрипт тестирования
echo -e "\n=== СОЗДАНИЕ ТЕСТОВОГО СКРИПТА ==="
cat > test_script.sh << 'EOL'
#!/bin/bash
set -e

check_output() {
    local output="$1"
    local pid="$2"

    if [[ ! "$output" =~ "Process ID: $pid" ]]; then
        echo "ОШИБКА: Не найден PID $pid в выводе"
        return 1
    fi

    if [[ ! "$output" =~ "User ID: " ]]; then
        echo "ОШИБКА: Не найден User ID"
        return 1
    fi

    if [[ ! "$output" =~ "Executable path: " ]]; then
        echo "ОШИБКА: Не найден путь к исполняемому файлу"
        return 1
    fi

    if [[ ! "$output" =~ "Command line: " ]]; then
        echo "ОШИБКА: Не найдена командная строка"
        return 1
    fi

    return 0
}

if ! lsmod | grep -q "process_info"; then
    echo "ОШИБКА: Модуль ядра не загружен"
    exit 1
fi

if [ ! -d "/sys/kernel/process_info" ]; then
    echo "ОШИБКА: Интерфейс sysfs не создан"
    exit 1
fi

echo "Запуск тестового процесса (sleep 60)..."
sleep 60 &
TEST_PID=$!
echo "Тестовый PID: $TEST_PID"
sleep 1

echo -e "\nТЕСТ 1: Проверка информации для PID $TEST_PID"
if ! OUTPUT1=$(./build/process_info_app $TEST_PID 2>&1); then
    echo "ОШИБКА выполнения программы"
    kill $TEST_PID
    exit 1
fi
echo "$OUTPUT1"
check_output "$OUTPUT1" $TEST_PID || { kill $TEST_PID; exit 1; }

echo -e "\nТЕСТ 2: Проверка информации для текущего shell PID $$"
if ! OUTPUT2=$(./build/process_info_app $$ 2>&1); then
    echo "ОШИБКА выполнения программы"
    kill $TEST_PID
    exit 1
fi
echo "$OUTPUT2"
check_output "$OUTPUT2" $$ || { kill $TEST_PID; exit 1; }

echo -e "\nТЕСТ 3: Проверка несуществующего PID"
if OUTPUT3=$(./build/process_info_app 999999 2>&1); then
    echo "ОШИБКА: Программа не вернула ошибку для несуществующего PID"
    kill $TEST_PID
    exit 1
else
    echo "Ожидаемая ошибка: $OUTPUT3"
fi

kill $TEST_PID

echo -e "\n=== ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО ==="
EOL

chmod +x test_script.sh

# 8. Сборка и установка
echo -e "\n=== СБОРКА И УСТАНОВКА ==="
echo "Сборка модуля ядра..."
make

echo "Сборка приложения..."
mkdir -p build
cd build
cmake ..
make
cd ..

echo "Установка модуля ядра..."
sudo insmod process_info.ko

if ! lsmod | grep -q "process_info"; then
    echo "ОШИБКА: Модуль не загрузился"
    exit 1
fi

# 9. Запуск тестов
echo -e "\n=== ЗАПУСК ТЕСТОВ ==="
./test_script.sh

# 10. Завершение
echo -e "\n=== ЗАВЕРШЕНИЕ ==="
echo -e "Для удаления модуля выполните:\n  sudo rmmod process_info"
echo -e "\nДля очистки:\n  make clean && rm -rf build"
echo -e "\n=== ГОТОВО ==="