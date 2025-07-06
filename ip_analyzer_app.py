import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket
import threading
import queue
import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

# --- DİL STRİNGLERİ (Tüm metinler burada yönetilir) ---
LANG_STRINGS = {
    # Genel
    'app_title': {'en': 'IP Analysis & Query Tool v4.0', 'tr': 'IP Analiz ve Sorgulama Aracı v4.0'},
    'file_menu': {'en': 'File', 'tr': 'Dosya'},
    'language_menu': {'en': 'Language', 'tr': 'Dil'},
    'exit_menu': {'en': 'Exit', 'tr': 'Çıkış'},
    'load_ip_button': {'en': 'Load IP List (.txt)', 'tr': 'IP Listesi Yükle (.txt)'},
    'load_ip_prompt_title': {'en': 'Select IP List File', 'tr': 'IP Listesi Dosyasını Seçin'},
    'info_label_default': {'en': 'Please load an IP list.', 'tr': 'Lütfen bir IP listesi yükleyin.'},
    'info_label_loaded': {'en': '{count} IP addresses loaded.', 'tr': '{count} IP adresi yüklendi.'},
    'info_label_empty': {'en': 'File is empty or contains no valid IPs.', 'tr': 'Dosya boş veya geçerli IP içermiyor.'},
    'error_title': {'en': 'Error', 'tr': 'Hata'},
    'file_read_error': {'en': 'An error occurred while reading the file: {e}', 'tr': 'Dosya okunurken bir hata oluştu: {e}'},
    'warning_title': {'en': 'Warning', 'tr': 'Uyarı'},
    'proc_is_running_warn': {'en': 'A process is already running.', 'tr': 'Hali hazırda bir işlem devam ediyor.'},
    'load_ip_first_warn': {'en': 'Please load an IP list first.', 'tr': 'Lütfen önce bir IP listesi yükleyin.'},
    'status_label_waiting': {'en': 'Status: Waiting', 'tr': 'Durum: Bekliyor'},
    'status_label_progress': {'en': 'Status: {current} / {total}', 'tr': 'Durum: {current} / {total}'},
    'status_label_stopped': {'en': 'Status: Stopped by user.', 'tr': 'Durum: Kullanıcı tarafından durduruldu.'},
    'completed_title': {'en': 'Completed', 'tr': 'Tamamlandı'},
    'query_completed_msg': {'en': 'Query process has been completed.', 'tr': 'Sorgulama işlemi tamamlandı.'},
    'stop_title': {'en': 'Stop', 'tr': 'Durdur'},
    'stop_confirm_msg': {'en': 'Are you sure you want to stop the process?', 'tr': 'İşlemi durdurmak istediğinizden emin misiniz?'},
    'stopped_title': {'en': 'Stopped', 'tr': 'Durduruldu'},
    'proc_stopped_msg': {'en': 'The process was stopped by the user.', 'tr': 'İşlem kullanıcı tarafından durduruldu.'},
    'no_data_to_save_msg': {'en': 'There is no data to save.', 'tr': 'Kaydedilecek veri bulunmamaktadır.'},
    'save_success_title': {'en': 'Success', 'tr': 'Başarılı'},
    'save_success_msg': {'en': 'Results have been saved successfully: {path}', 'tr': 'Sonuçlar başarıyla kaydedildi: {path}'},
    'save_error_msg': {'en': 'An error occurred while saving the file: {e}', 'tr': 'Dosya kaydedilirken bir hata oluştu: {e}'},
    'concurrent_query_label': {'en': 'Concurrent Queries:', 'tr': 'Eş Zamanlı Sorgu:'},
    'start_button': {'en': 'Start', 'tr': 'Başlat'},
    'pause_button': {'en': 'Pause', 'tr': 'Duraklat'},
    'resume_button': {'en': 'Resume', 'tr': 'Devam Et'},
    'stop_button': {'en': 'Stop', 'tr': 'Durdur'},
    'save_results_button': {'en': 'Save Results', 'tr': 'Sonuçları Kaydet'},

    # DNS & ASN Sekmesi
    'dns_tab_title': {'en': 'DNS & ASN Lookup', 'tr': 'DNS & ASN Sorgulama'},
    'ip_col': {'en': 'IP Address', 'tr': 'IP Adresi'},
    'hostname_col': {'en': 'Hostname (PTR)', 'tr': 'Hostname (PTR)'},
    'asn_col': {'en': 'ASN', 'tr': 'ASN'},
    'provider_col': {'en': 'Provider', 'tr': 'Sağlayıcı'},
    'ptr_not_found': {'en': 'PTR not found', 'tr': 'PTR bulunamadı'},
    'private_ip': {'en': 'Private / Local IP', 'tr': 'Özel / Lokal IP'},
    'asn_query_error': {'en': 'ASN Query Error', 'tr': 'ASN Sorgu Hatası'},
    'save_dns_title': {'en': 'Save DNS Results', 'tr': 'DNS Sonuçlarını Kaydet'},

    # Spamhaus Sekmesi
    'spamhaus_tab_title': {'en': 'Spamhaus Lookup', 'tr': 'Spamhaus Sorgulama'},
    'status_col': {'en': 'Status', 'tr': 'Durum'},
    'spamhaus_code_col': {'en': 'Spamhaus Code', 'tr': 'Spamhaus Kodu'},
    'listed_status': {'en': '❌ Listed', 'tr': '❌ Listede'},
    'clean_status': {'en': '✅ Clean', 'tr': '✅ Temiz'},
    'error_status': {'en': 'Error', 'tr': 'Hata'},
    'save_spam_button': {'en': 'Save Listed IPs', 'tr': 'Listelenen IP\'leri Kaydet'},
    'save_spam_title': {'en': 'Save Spamhaus Listed IPs', 'tr': 'Spamhaus Listesindeki IP\'leri Kaydet'},
    'no_spam_to_save': {'en': 'No listed IPs found to save.', 'tr': 'Kaydedilecek listelenmiş IP bulunmamaktadır.'},
    'spam_save_header': {'en': 'IP Addresses Found in Spamhaus Blacklist', 'tr': 'Spamhaus Kara Listesinde Bulunan IP Adresleri'},
    'spam_save_return_code': {'en': 'Return Code', 'tr': 'Dönüş Kodu'},

    # AbuseIPDB Sekmesi
    'abuse_tab_title': {'en': 'AbuseIPDB Lookup', 'tr': 'AbuseIPDB Sorgulama'},
    'api_key_label': {'en': 'AbuseIPDB API Key:', 'tr': 'AbuseIPDB API Key:'},
    'api_key_error': {'en': 'Please enter your AbuseIPDB API key.', 'tr': 'Lütfen AbuseIPDB API anahtarınızı girin.'},
    'score_col': {'en': 'Confidence Score (%)', 'tr': 'Güven Skoru (%)'},
    'reports_col': {'en': 'Total Reports', 'tr': 'Toplam Rapor'},
    'country_col': {'en': 'Country', 'tr': 'Ülke'},
    'isp_col': {'en': 'ISP', 'tr': 'ISP'},
    'domain_col': {'en': 'Domain', 'tr': 'Domain'},
    'api_error_unknown': {'en': 'Unknown API Error', 'tr': 'Bilinmeyen API Hatası'},
    'network_error': {'en': 'Network Error', 'tr': 'Ağ Hatası'},
    'save_abuse_title': {'en': 'Save AbuseIPDB Results', 'tr': 'AbuseIPDB Sonuçlarını Kaydet'},
}

class IPAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # --- Ana Değişkenler ---
        self.ip_list = []
        self.result_queue = queue.Queue()
        self.is_running = False
        self.stop_requested = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.current_lang = tk.StringVar(value='en')
        self.current_lang.trace_add('write', self.update_ui_language)

        self.geometry("1000x750")

        self.style = ttk.Style(self)
        self.style.layout('text.Horizontal.TProgressbar',
                         [('Horizontal.Progressbar.trough', {'children': [('Horizontal.Progressbar.pbar', {'side': 'left', 'sticky': 'ns'})], 'sticky': 'nswe'}),
                          ('Horizontal.Progressbar.label', {'sticky': ''})])
        self.style.configure('text.Horizontal.TProgressbar', text='0 %', anchor='center')

        self.create_widgets()
        self.update_ui_language()
        self.process_queue()

    def get_text(self, key):
        return LANG_STRINGS.get(key, {}).get(self.current_lang.get(), key)

    def create_widgets(self):
        # --- Menü Çubuğu ---
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label=self.get_text('file_menu'), menu=self.file_menu)
        
        self.language_menu = tk.Menu(self.file_menu, tearoff=0)
        self.file_menu.add_cascade(label=self.get_text('language_menu'), menu=self.language_menu)
        self.language_menu.add_radiobutton(label="English", variable=self.current_lang, value='en')
        self.language_menu.add_radiobutton(label="Türkçe", variable=self.current_lang, value='tr')
        self.file_menu.add_separator()
        self.file_menu.add_command(label=self.get_text('exit_menu'), command=self.quit)

        # --- Ana Arayüz ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.LabelFrame(main_frame, text=self.get_text('control_panel_title'), padding="10")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.load_button = ttk.Button(top_frame, text=self.get_text('load_ip_button'), command=self.load_ip_file)
        self.load_button.pack(side=tk.LEFT, padx=(0, 10))
        self.info_label = ttk.Label(top_frame, text=self.get_text('info_label_default'))
        self.info_label.pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.create_dns_tab()
        self.create_spam_tab()
        self.create_abuseipdb_tab()

    def update_ui_language(self, *args):
        self.title(self.get_text('app_title'))
        # Menü
        self.menu_bar.entryconfig(1, label=self.get_text('file_menu'))
        self.file_menu.entryconfig(0, label=self.get_text('language_menu'))
        self.file_menu.entryconfig(2, label=self.get_text('exit_menu'))
        # Ana Kontroller
        self.load_button.config(text=self.get_text('load_ip_button'))
        # Sekme Başlıkları
        self.notebook.tab(0, text=self.get_text('dns_tab_title'))
        self.notebook.tab(1, text=self.get_text('spamhaus_tab_title'))
        self.notebook.tab(2, text=self.get_text('abuse_tab_title'))
        # Her sekmenin içindeki widget'ları güncelle
        self.update_dns_tab_lang()
        self.update_spam_tab_lang()
        self.update_abuse_tab_lang()

    def create_generic_tab_controls(self, parent, threads_var):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, pady=(0, 5))
        
        label = ttk.Label(control_frame, text=self.get_text('concurrent_query_label'))
        label.pack(side=tk.LEFT, padx=(0, 5))
        
        combo = ttk.Combobox(control_frame, textvariable=threads_var, values=["5", "10", "20", "50", "100"], width=5)
        combo.pack(side=tk.LEFT, padx=(0, 10))
        
        start_button = ttk.Button(control_frame, text=self.get_text('start_button'))
        start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        pause_button = ttk.Button(control_frame, text=self.get_text('pause_button'), state=tk.DISABLED)
        pause_button.pack(side=tk.LEFT, padx=(0, 5))
        
        stop_button = ttk.Button(control_frame, text=self.get_text('stop_button'), state=tk.DISABLED)
        stop_button.pack(side=tk.LEFT)
        
        return control_frame, label, combo, start_button, pause_button, stop_button

    def create_generic_progress_area(self, parent):
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, pady=5)
        status_label = ttk.Label(progress_frame, text=self.get_text('status_label_waiting'))
        status_label.pack(fill=tk.X)
        progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', mode='determinate', style='text.Horizontal.TProgressbar')
        progress_bar.pack(fill=tk.X, expand=True)
        return status_label, progress_bar

    def create_generic_treeview(self, parent, columns, headings):
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 5))
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col, head_key in headings.items():
            tree.heading(col, text=self.get_text(head_key), command=lambda c=col: self.sort_treeview_column(tree, c, False))
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return tree

    def create_dns_tab(self):
        self.dns_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.dns_tab, text=self.get_text('dns_tab_title'))
        
        self.dns_threads_var = tk.StringVar(value="10")
        controls = self.create_generic_tab_controls(self.dns_tab, self.dns_threads_var)
        self.dns_control_label, self.dns_start_button, self.dns_pause_button, self.dns_stop_button = controls[1], controls[3], controls[4], controls[5]
        self.dns_start_button.config(command=self.start_dns_query)
        self.dns_pause_button.config(command=self.toggle_pause_resume)
        self.dns_stop_button.config(command=self.stop_query)

        self.dns_status_label, self.dns_progress = self.create_generic_progress_area(self.dns_tab)
        
        cols = ("ip", "hostname", "asn", "provider")
        headings = {'ip': 'ip_col', 'hostname': 'hostname_col', 'asn': 'asn_col', 'provider': 'provider_col'}
        self.dns_tree = self.create_generic_treeview(self.dns_tab, cols, headings)
        self.dns_tree.column("ip", width=120, stretch=tk.NO); self.dns_tree.column("hostname", width=250); self.dns_tree.column("asn", width=80, stretch=tk.NO); self.dns_tree.column("provider", width=300)

        self.dns_save_button = ttk.Button(self.dns_tab, text=self.get_text('save_results_button'), command=self.save_dns_results)
        self.dns_save_button.pack(pady=(5,0))

    def update_dns_tab_lang(self):
        self.dns_control_label.config(text=self.get_text('concurrent_query_label'))
        self.dns_start_button.config(text=self.get_text('start_button'))
        self.dns_pause_button.config(text=self.get_text('pause_button') if self.pause_event.is_set() else self.get_text('resume_button'))
        self.dns_stop_button.config(text=self.get_text('stop_button'))
        self.dns_save_button.config(text=self.get_text('save_results_button'))
        for col, head_key in {'ip': 'ip_col', 'hostname': 'hostname_col', 'asn': 'asn_col', 'provider': 'provider_col'}.items():
            self.dns_tree.heading(col, text=self.get_text(head_key))

    def create_spam_tab(self):
        self.spam_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.spam_tab, text=self.get_text('spamhaus_tab_title'))

        self.spam_threads_var = tk.StringVar(value="10")
        controls = self.create_generic_tab_controls(self.spam_tab, self.spam_threads_var)
        self.spam_control_label, self.spam_start_button, self.spam_pause_button, self.spam_stop_button = controls[1], controls[3], controls[4], controls[5]
        self.spam_start_button.config(command=self.start_spam_check)
        self.spam_pause_button.config(command=self.toggle_pause_resume)
        self.spam_stop_button.config(command=self.stop_query)

        self.spam_status_label, self.spam_progress = self.create_generic_progress_area(self.spam_tab)

        cols = ("ip", "status", "code")
        headings = {'ip': 'ip_col', 'status': 'status_col', 'code': 'spamhaus_code_col'}
        self.spam_tree = self.create_generic_treeview(self.spam_tab, cols, headings)
        self.spam_tree.column("ip", width=150, stretch=tk.NO); self.spam_tree.column("status", width=150); self.spam_tree.column("code", width=450)

        self.spam_save_button = ttk.Button(self.spam_tab, text=self.get_text('save_spam_button'), command=self.save_spam_results)
        self.spam_save_button.pack(pady=(5,0))

    def update_spam_tab_lang(self):
        self.spam_control_label.config(text=self.get_text('concurrent_query_label'))
        self.spam_start_button.config(text=self.get_text('start_button'))
        self.spam_pause_button.config(text=self.get_text('pause_button') if self.pause_event.is_set() else self.get_text('resume_button'))
        self.spam_stop_button.config(text=self.get_text('stop_button'))
        self.spam_save_button.config(text=self.get_text('save_spam_button'))
        for col, head_key in {'ip': 'ip_col', 'status': 'status_col', 'code': 'spamhaus_code_col'}.items():
            self.spam_tree.heading(col, text=self.get_text(head_key))

    def create_abuseipdb_tab(self):
        self.abuse_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.abuse_tab, text=self.get_text('abuse_tab_title'))

        abuse_control_frame = ttk.Frame(self.abuse_tab)
        abuse_control_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.abuse_api_label = ttk.Label(abuse_control_frame, text=self.get_text('api_key_label'))
        self.abuse_api_label.pack(side=tk.LEFT, padx=(0, 5))
        self.abuseipdb_api_key_var = tk.StringVar()
        ttk.Entry(abuse_control_frame, textvariable=self.abuseipdb_api_key_var, width=40).pack(side=tk.LEFT, padx=(0, 10))
        
        self.abuse_threads_var = tk.StringVar(value="10")
        inner_controls_frame = ttk.Frame(abuse_control_frame)
        inner_controls_frame.pack(side=tk.LEFT)
        controls = self.create_generic_tab_controls(inner_controls_frame, self.abuse_threads_var)
        self.abuse_control_label, self.abuse_start_button, self.abuse_pause_button, self.abuse_stop_button = controls[1], controls[3], controls[4], controls[5]
        self.abuse_start_button.config(command=self.start_abuseipdb_check)
        self.abuse_pause_button.config(command=self.toggle_pause_resume)
        self.abuse_stop_button.config(command=self.stop_query)

        self.abuse_status_label, self.abuse_progress = self.create_generic_progress_area(self.abuse_tab)
        
        cols = ("ip", "score", "reports", "country", "isp", "domain")
        headings = {'ip': 'ip_col', 'score': 'score_col', 'reports': 'reports_col', 'country': 'country_col', 'isp': 'isp_col', 'domain': 'domain_col'}
        self.abuse_tree = self.create_generic_treeview(self.abuse_tab, cols, headings)
        self.abuse_tree.column("ip", width=120, stretch=tk.NO); self.abuse_tree.column("score", width=100, stretch=tk.NO); self.abuse_tree.column("reports", width=100, stretch=tk.NO); self.abuse_tree.column("country", width=80); self.abuse_tree.column("isp", width=250); self.abuse_tree.column("domain", width=200)

        self.abuse_save_button = ttk.Button(self.abuse_tab, text=self.get_text('save_results_button'), command=self.save_abuse_results)
        self.abuse_save_button.pack(pady=(5,0))

    def update_abuse_tab_lang(self):
        self.abuse_api_label.config(text=self.get_text('api_key_label'))
        self.abuse_control_label.config(text=self.get_text('concurrent_query_label'))
        self.abuse_start_button.config(text=self.get_text('start_button'))
        self.abuse_pause_button.config(text=self.get_text('pause_button') if self.pause_event.is_set() else self.get_text('resume_button'))
        self.abuse_stop_button.config(text=self.get_text('stop_button'))
        self.abuse_save_button.config(text=self.get_text('save_results_button'))
        for col, head_key in {'ip': 'ip_col', 'score': 'score_col', 'reports': 'reports_col', 'country': 'country_col', 'isp': 'isp_col', 'domain': 'domain_col'}.items():
            self.abuse_tree.heading(col, text=self.get_text(head_key))

    def load_ip_file(self):
        file_path = filedialog.askopenfilename(title=self.get_text('load_ip_prompt_title'), filetypes=[("Text Files", "*.txt"), ("All files", "*.*")])
        if not file_path: return
        try:
            with open(file_path, 'r') as f:
                self.ip_list = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if self.ip_list:
                self.info_label.config(text=self.get_text('info_label_loaded').format(count=len(self.ip_list)))
                self.dns_tree.delete(*self.dns_tree.get_children())
                self.spam_tree.delete(*self.spam_tree.get_children())
                self.abuse_tree.delete(*self.abuse_tree.get_children())
            else:
                self.info_label.config(text=self.get_text('info_label_empty'))
        except Exception as e:
            messagebox.showerror(self.get_text('error_title'), self.get_text('file_read_error').format(e=e))

    def start_query(self, target_worker, progress_bar, treeview, status_label, threads_var):
        if self.is_running: messagebox.showwarning(self.get_text('warning_title'), self.get_text('proc_is_running_warn')); return
        if not self.ip_list: messagebox.showwarning(self.get_text('warning_title'), self.get_text('load_ip_first_warn')); return
        treeview.delete(*treeview.get_children())
        progress_bar['maximum'] = len(self.ip_list); progress_bar['value'] = 0
        status_label.config(text=self.get_text('status_label_progress').format(current=0, total=len(self.ip_list)))
        
        num_threads = int(threads_var.get())
        ip_queue = queue.Queue()
        for ip in self.ip_list: ip_queue.put(ip)
        self.is_running = True; self.stop_requested = False; self.pause_event.set()
        self.toggle_controls(False)
        for _ in range(num_threads):
            thread = threading.Thread(target=target_worker, args=(ip_queue,), daemon=True)
            thread.start()

    def start_dns_query(self): self.start_query(self.dns_worker, self.dns_progress, self.dns_tree, self.dns_status_label, self.dns_threads_var)
    def start_spam_check(self): self.start_query(self.spam_worker, self.spam_progress, self.spam_tree, self.spam_status_label, self.spam_threads_var)
    def start_abuseipdb_check(self):
        if not self.abuseipdb_api_key_var.get():
            messagebox.showerror(self.get_text('error_title'), self.get_text('api_key_error')); return
        self.start_query(self.abuseipdb_worker, self.abuse_progress, self.abuse_tree, self.abuse_status_label, self.abuse_threads_var)

    def dns_worker(self, q):
        while not q.empty() and not self.stop_requested:
            self.pause_event.wait(); ip = q.get()
            hostname, asn, provider = self.get_text('ptr_not_found'), "N/A", "N/A"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                obj = IPWhois(ip); results = obj.lookup_whois()
                asn = results.get('asn', 'N/A'); provider = results.get('asn_description', 'N/A')
            except socket.herror: pass
            except IPDefinedError: provider = self.get_text('private_ip')
            except Exception: provider = self.get_text('asn_query_error')
            self.result_queue.put(("dns", (ip, hostname, asn, provider))); q.task_done()

    def spam_worker(self, q):
        while not q.empty() and not self.stop_requested:
            self.pause_event.wait(); ip = q.get()
            try:
                reversed_ip = '.'.join(reversed(ip.strip().split('.')))
                query = f"{reversed_ip}.zen.spamhaus.org"
                result = socket.gethostbyname(query)
                self.result_queue.put(("spam", (ip, self.get_text('listed_status'), result)))
            except socket.gaierror: self.result_queue.put(("spam", (ip, self.get_text('clean_status'), "-")))
            except Exception as e: self.result_queue.put(("spam", (ip, self.get_text('error_status'), str(e))))
            q.task_done()

    def abuseipdb_worker(self, q):
        api_key = self.abuseipdb_api_key_var.get()
        headers = {'Key': api_key, 'Accept': 'application/json'}
        while not q.empty() and not self.stop_requested:
            self.pause_event.wait(); ip = q.get()
            querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
            try:
                response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring, timeout=10)
                if response.status_code == 200:
                    data = response.json()['data']
                    score, reports, country, isp, domain = data.get('abuseConfidenceScore', 0), data.get('totalReports', 0), data.get('countryCode', 'N/A'), data.get('isp', 'N/A'), data.get('domain', 'N/A')
                    self.result_queue.put(("abuse", (ip, score, reports, country, isp, domain)))
                else:
                    error_msg = response.json().get('errors', [{}])[0].get('detail', self.get_text('api_error_unknown'))
                    self.result_queue.put(("abuse", (ip, self.get_text('error_status'), error_msg, '-', '-', '-')))
            except requests.exceptions.RequestException:
                self.result_queue.put(("abuse", (ip, self.get_text('error_status'), self.get_text('network_error'), '-', '-', '-')))
            q.task_done()

    def process_queue(self):
        try:
            processed_count = 0
            while processed_count < 100:
                task_type, data = self.result_queue.get_nowait()
                if task_type == "dns": tree, progress, status_label = self.dns_tree, self.dns_progress, self.dns_status_label
                elif task_type == "spam": tree, progress, status_label = self.spam_tree, self.spam_progress, self.spam_status_label
                elif task_type == "abuse": tree, progress, status_label = self.abuse_tree, self.abuse_progress, self.abuse_status_label
                else: continue
                
                tree.insert("", "end", values=data); progress['value'] += 1
                current_progress = progress['value']; max_progress = progress['maximum']
                percent = int((current_progress / max_progress) * 100) if max_progress > 0 else 0
                status_label.config(text=self.get_text('status_label_progress').format(current=current_progress, total=max_progress))
                self.style.configure('text.Horizontal.TProgressbar', text=f'{percent} %')
                
                if current_progress >= max_progress:
                    if self.is_running:
                        self.is_running = False; self.toggle_controls(True)
                        messagebox.showinfo(self.get_text('completed_title'), self.get_text('query_completed_msg'))
                processed_count += 1
        except queue.Empty: pass
        finally: self.after(100, self.process_queue)
    
    def toggle_controls(self, state):
        status = tk.NORMAL if state else tk.DISABLED
        pause_status = tk.DISABLED if state else tk.NORMAL
        self.load_button.config(state=status)
        for btn in [self.dns_start_button, self.spam_start_button, self.abuse_start_button]: btn.config(state=status)
        for btn in [self.dns_pause_button, self.dns_stop_button, self.spam_pause_button, self.spam_stop_button, self.abuse_pause_button, self.abuse_stop_button]: btn.config(state=pause_status)
        if state:
             for btn in [self.dns_pause_button, self.spam_pause_button, self.abuse_pause_button]: btn.config(text=self.get_text('pause_button'))

    def toggle_pause_resume(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            for btn in [self.dns_pause_button, self.spam_pause_button, self.abuse_pause_button]: btn.config(text=self.get_text('resume_button'))
        else:
            self.pause_event.set()
            for btn in [self.dns_pause_button, self.spam_pause_button, self.abuse_pause_button]: btn.config(text=self.get_text('pause_button'))

    def stop_query(self):
        if not self.is_running: return
        if messagebox.askyesno(self.get_text('stop_title'), self.get_text('stop_confirm_msg')):
            self.stop_requested = True; self.is_running = False; self.pause_event.set()
            self.toggle_controls(True)
            for label in [self.dns_status_label, self.spam_status_label, self.abuse_status_label]: label.config(text=self.get_text('status_label_stopped'))
            messagebox.showinfo(self.get_text('stopped_title'), self.get_text('proc_stopped_msg'))

    def sort_treeview_column(self, tv, col, reverse):
        try:
            data_list = [(tv.set(k, col), k) for k in tv.get_children('')]
            if col == 'ip': data_list.sort(key=lambda t: list(map(int, t[0].split('.'))), reverse=reverse)
            elif col in ['score', 'reports']: data_list.sort(key=lambda t: int(str(t[0]).strip() or 0), reverse=reverse)
            else: data_list.sort(key=lambda t: str(t[0]).lower(), reverse=reverse)
            for index, (val, k) in enumerate(data_list): tv.move(k, '', index)
            tv.heading(col, command=lambda: self.sort_treeview_column(tv, col, not reverse))
        except (ValueError, IndexError):
            data_list.sort(key=lambda t: str(t[0]), reverse=reverse)
            for index, (val, k) in enumerate(data_list): tv.move(k, '', index)
            tv.heading(col, command=lambda: self.sort_treeview_column(tv, col, not reverse))

    def save_dns_results(self):
        if not self.dns_tree.get_children(): messagebox.showinfo(self.get_text('warning_title'), self.get_text('no_data_to_save_msg')); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")], title=self.get_text('save_dns_title'))
        if not file_path: return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"{self.get_text('ip_col'):<20}{self.get_text('hostname_col'):<40}{self.get_text('asn_col'):<15}{self.get_text('provider_col')}\n"); f.write(f"{'-'*20}{'-'*40}{'-'*15}{'-'*40}\n")
                for item in self.dns_tree.get_children():
                    row = self.dns_tree.item(item)['values']
                    f.write(f"{str(row[0]):<20}{str(row[1]):<40}{str(row[2]):<15}{str(row[3])}\n")
            messagebox.showinfo(self.get_text('save_success_title'), self.get_text('save_success_msg').format(path=file_path))
        except Exception as e: messagebox.showerror(self.get_text('error_title'), self.get_text('save_error_msg').format(e=e))

    def save_spam_results(self):
        spam_ips = [self.spam_tree.item(item, 'values') for item in self.spam_tree.get_children() if self.get_text('listed_status') in self.spam_tree.item(item, 'values')[1]]
        if not spam_ips: messagebox.showinfo(self.get_text('warning_title'), self.get_text('no_spam_to_save')); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")], title=self.get_text('save_spam_title'))
        if not file_path: return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"{self.get_text('spam_save_header')}\n"); f.write("-------------------------------------------\n")
                for ip_data in spam_ips: f.write(f"{ip_data[0]} - {self.get_text('spam_save_return_code')}: {ip_data[2]}\n")
            messagebox.showinfo(self.get_text('save_success_title'), self.get_text('save_success_msg').format(path=file_path))
        except Exception as e: messagebox.showerror(self.get_text('error_title'), self.get_text('save_error_msg').format(e=e))
        
    def save_abuse_results(self):
        if not self.abuse_tree.get_children(): messagebox.showinfo(self.get_text('warning_title'), self.get_text('no_data_to_save_msg')); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")], title=self.get_text('save_abuse_title'))
        if not file_path: return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"{self.get_text('ip_col'):<18}{self.get_text('score_col'):<20}{self.get_text('reports_col'):<15}{self.get_text('country_col'):<10}{self.get_text('isp_col'):<40}{self.get_text('domain_col')}\n")
                f.write(f"{'-'*18}{'-'*20}{'-'*15}{'-'*10}{'-'*40}{'-'*30}\n")
                for item in self.abuse_tree.get_children():
                    row = self.abuse_tree.item(item)['values']
                    f.write(f"{str(row[0]):<18}{str(row[1]):<20}{str(row[2]):<15}{str(row[3]):<10}{str(row[4]):<40}{str(row[5])}\n")
            messagebox.showinfo(self.get_text('save_success_title'), self.get_text('save_success_msg').format(path=file_path))
        except Exception as e: messagebox.showerror(self.get_text('error_title'), self.get_text('save_error_msg').format(e=e))

if __name__ == "__main__":
    app = IPAnalyzerApp()
    app.mainloop()
