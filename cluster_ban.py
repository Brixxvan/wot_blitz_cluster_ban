import os
import ctypes
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, StringVar
from pythonping import ping
import threading

# Путь к файлу hosts
HOSTS_PATH = r"C:\\Windows\\System32\\drivers\\etc\\hosts"

# Кластеры и их адреса
WG_CLUSTERS = {
    "C0": "127.0.0.1 login0.wotblitz.eu",
    "C1": "127.0.0.1 login1.wotblitz.eu",
    "C2": "127.0.0.1 login2.wotblitz.eu",
    "C3": "127.0.0.1 login3.wotblitz.eu",
    "C4": "127.0.0.1 login4.wotblitz.eu",
}

LESTA_CLUSTERS = {
    "C0": "127.0.0.1 login0.tanksblitz.ru",
    "C1": "127.0.0.1 login1.tanksblitz.ru",
    "C2": "127.0.0.1 login2.tanksblitz.ru",
    "C3": "127.0.0.1 login3.tanksblitz.ru",
    "C4": "127.0.0.1 login4.tanksblitz.ru",
    "C5": "127.0.0.1 login5.tanksblitz.ru",
}

ASIA_CLUSTERS = {
    "C0": "127.0.0.1 login0.wotblitz.asia",
    "C1": "127.0.0.1 login1.wotblitz.asia",
    "C2": "127.0.0.1 login2.wotblitz.asia",
}

NA_CLUSTERS = {
    "C0": "127.0.0.1 login0.wotblitz.com",
    "C1": "127.0.0.1 login1.wotblitz.com",
    "C2": "127.0.0.1 login2.wotblitz.com",
}

def set_file_permissions():
    try:
        print("Попытка изменения атрибутов файла...")
        ctypes.windll.kernel32.SetFileAttributesW(HOSTS_PATH, 0x80)  # FILE_ATTRIBUTE_NORMAL
        os.chmod(HOSTS_PATH, 0o666)
        print("Атрибуты файла изменены.")
        if not os.access(HOSTS_PATH, os.W_OK):
            raise PermissionError("Файл недоступен для записи.")
    except Exception as e:
        print(f"Ошибка при изменении прав: {e}")
        messagebox.showerror("Ошибка", f"Не удалось изменить права доступа: {e}")

def update_hosts(block_clusters, clusters):
    try:
        set_file_permissions()
        with open(HOSTS_PATH, "r") as file:
            lines = file.readlines()

        # Удаляем строки, связанные с кластерами
        lines = [line for line in lines if not any(cluster in line for cluster in clusters.values())]

        # Добавляем выбранные кластеры
        for cluster in block_clusters:
            lines.append(f"{clusters[cluster]}\n")

        with open(HOSTS_PATH, "w") as file:
            file.writelines(lines)

        return True
    except PermissionError:
        messagebox.showerror("Ошибка", "Запустите программу от имени администратора.")
        return False
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")
        return False

def unblock_all(clusters):
    try:
        set_file_permissions()
        with open(HOSTS_PATH, "r") as file:
            lines = file.readlines()

        # Удаляем строки, которые точно соответствуют строкам в clusters
        new_lines = [line for line in lines if line.strip() not in clusters]

        if len(new_lines) == len(lines):
            messagebox.showinfo("Информация", "Ни один кластер не был заблокирован.")
            return

        with open(HOSTS_PATH, "w") as file:
            file.writelines(new_lines)

        messagebox.showinfo("Информация", "Все кластеры разблокированы!")
    except PermissionError:
        messagebox.showerror("Ошибка", "Запустите программу от имени администратора.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")

def block_selected(tab_name):
    selected_clusters = [cluster for cluster, var in cluster_vars[tab_name].items() if var.get() == 1]
    cluster_mapping = {
        "WG: EU": WG_CLUSTERS,
        "Lesta: RU": LESTA_CLUSTERS,
        "WG: ASIA": ASIA_CLUSTERS,
        "WG: NA": NA_CLUSTERS,
    }
    clusters = cluster_mapping.get(tab_name)

    if len(selected_clusters) == len(clusters):
        messagebox.showerror("Ошибка", "Нельзя заблокировать сразу все кластеры.")
        return

    if selected_clusters:
        if update_hosts(selected_clusters, clusters):
            messagebox.showinfo("Информация", f"Кластеры {', '.join(selected_clusters)} заблокированы!")
    else:
        messagebox.showwarning("Предупреждение", "Выберите хотя бы один кластер.")

def ping_server(server_url):
    try:
        response = ping(server_url, count=5)
        if response.success():
            return f"Средняя задержка: {response.rtt_avg_ms:.2f} ms"
        else:
            return "Недоступен"
    except Exception as e:
        return f"Ошибка: {e}"

def test_clusters_async(tab_name, status_var):
    status_var.set("Идет проверка...")
    cluster_mapping = {
        "WG: EU": WG_CLUSTERS,
        "Lesta: RU": LESTA_CLUSTERS,
        "WG: ASIA": ASIA_CLUSTERS,
        "WG: NA": NA_CLUSTERS,
    }
    clusters = cluster_mapping.get(tab_name)
    if not clusters:
        return

    results = []
    for cluster, address in clusters.items():
        domain = address.split()[-1]  # Извлекаем доменное имя
        status = ping_server(domain)
        results.append(f"{cluster}: {status}")

    status_var.set("")
    messagebox.showinfo("Результаты проверки", "\n".join(results))

def test_clusters(tab_name, status_var):
    threading.Thread(target=test_clusters_async, args=(tab_name, status_var), daemon=True).start()

# Создаем окно
root = ttk.Window(themename="litera")
root.title("Cluster Ban 2.0")
root.geometry("415x250")
root.resizable(False, False)

# Создаем вкладки
notebook = ttk.Notebook(root)
notebook.pack(fill=BOTH, expand=TRUE)

cluster_vars = {"WG: EU": {}, "Lesta: RU": {}, "WG: ASIA": {}, "WG: NA": {}}
status_var = StringVar(value="")

for tab_name, clusters in zip(["WG: EU", "Lesta: RU", "WG: ASIA", "WG: NA"], [WG_CLUSTERS, LESTA_CLUSTERS, ASIA_CLUSTERS, NA_CLUSTERS]):
    frame = ttk.Frame(notebook, padding=10)
    notebook.add(frame, text=tab_name)

    # Заголовок
    title_label = ttk.Label(frame, text=f"Выберите кластеры {tab_name} для блокировки:", font=("Helvetica", 12))
    title_label.pack(pady=10)

    # Чекбоксы
    checkbox_frame = ttk.Frame(frame)
    checkbox_frame.pack(pady=5)
    cluster_vars[tab_name] = {cluster: ttk.IntVar() for cluster in clusters}
    for cluster, var in cluster_vars[tab_name].items():
        ttk.Checkbutton(checkbox_frame, text=cluster, variable=var).pack(side=LEFT, padx=5, pady=5)

    # Кнопки
    button_frame = ttk.Frame(frame, padding=10)
    button_frame.pack(fill=BOTH, expand=TRUE)

    block_button = ttk.Button(button_frame, text="Заблокировать выбранные", command=lambda tn=tab_name: block_selected(tn), bootstyle=SUCCESS)
    block_button.pack(side=LEFT, padx=10, pady=10)
    block_button.configure(style="block.TButton")

    unblock_button = ttk.Button(
        button_frame,
        text="Разблокировать все",
        command=lambda: unblock_all(
            [value for cluster_dict in [WG_CLUSTERS, LESTA_CLUSTERS, ASIA_CLUSTERS, NA_CLUSTERS] for value in cluster_dict.values()]
        ),
        bootstyle=DANGER
    )
    unblock_button.pack(side=LEFT, padx=10, pady=10)
    unblock_button.configure(style="unblock.TButton")
    # Настройка стилей кнопок
    style = ttk.Style()
    style.configure("block.TButton", background="#ea4335", foreground="white", font=("Helvetica", 10), borderwidth=0, relief="flat")
    style.configure("unblock.TButton", background="#34a853", foreground="white", font=("Helvetica", 10), borderwidth=0, relief="flat")

    # Обновление стиля активной вкладки
    style.configure("TNotebook.Tab", font=("Helvetica", 10))
    style.map("TNotebook.Tab", 
              font=[("selected", ("Helvetica", 10, "bold"))],
              foreground=[("selected", "#000000")])

    # Заполняем вкладки равномерно
    notebook.pack(fill=BOTH, expand=True, padx=5, pady=5)

# Нижняя панель
footer_frame = ttk.Frame(root)
footer_frame.pack(side=BOTTOM, fill=X, padx=10, pady=5)

test_button = ttk.Button(
    footer_frame,
    text="Проверить PING",
    command=lambda: test_clusters(notebook.tab(notebook.select(), "text"), status_var),
    bootstyle=INFO
)
test_button.pack(side=LEFT, padx=10)

footer_label = ttk.Label(footer_frame, text="Created by BRIXXVAN", font=("Helvetica", 10), anchor="e")
footer_label.pack(side=RIGHT)

status_label = ttk.Label(footer_frame, textvariable=status_var, font=("Helvetica", 10), anchor="w")
status_label.pack(side=LEFT, padx=10)

# Запуск приложения
root.mainloop()