import subprocess
from email.mime.text import MIMEText
from jira import JIRA
from datetime import datetime, timedelta

# Настройки подключения к Jira
jira_options = {'server': 'https://jira.****.ru/'}
jira = JIRA(options=jira_options, basic_auth=('user_jira', 'P@@ssword'))

# Функция для отправки письма с использованием sendemail
def send_email(to_address, subject, message, attachment=None):
    command = [
        'sendemail',
        '-f', 'alert_critical@**.eu',
        '-t', to_address,
        '-u', subject,
        '-m', message,
        '-s', 'smtp.main.**.eu',
        '-o', 'tls=yes',
        '-o', 'message-charset=utf-8'  # Добавлено для указания кодировки
    ]
    if attachment:
        command.extend(['-a', attachment])

    try:
        subprocess.run(command, check=True)
        print(f'Письмо отправлено на {to_address}')
    except subprocess.CalledProcessError as e:
        print(f'Ошибка при отправке письма на {to_address}: {e}')

# Чтение уязвимых IP-адресов из файла
with open('vuln.txt', 'r') as file:
    vulnerable_ips = [line.strip() for line in file]

# Определение даты, до которой тикеты считаются старыми (например, 1 год назад)
cutoff_date = datetime.now() - timedelta(days=365)
cutoff_date_str = cutoff_date.strftime('%Y-%m-%d')

# Функция для выполнения поиска и добавления комментариев
def search_and_comment(jql_query, ip):
    issues = jira.search_issues(jql_query)
    for issue in issues:
        reporter = issue.fields.reporter
        reporter_name = reporter.displayName
        reporter_email = reporter.emailAddress
        reporter_active = reporter.active
        manager_name = issue.fields.customfield_18814  # Замените customfield_18814 на реальное поле для "Involved Managers"
        manager_email = issue.fields.customfield_18815  # Замените customfield_18815 на реальное поле для email менеджера

        # Отправка письма репортеру
        email_subject = "Уведомление о критической уязвимости"
        email_message = f"Уважаемый {reporter_name},\n\nПожалуйста, свяжитесь с отделом кибербезопасности. IP-адрес {ip} уязвим."
        send_email(reporter_email, email_subject, email_message)
        print(f'Письмо отправлено репортеру {reporter_name} для IP-адреса {ip}')

        if reporter_active:
            comment_text = f"@{reporter_name}, пожалуйста, свяжитесь с отделом кибербезопасности. IP-адрес {ip} уязвим."
            jira.add_comment(issue, comment_text)
        else:
            comment_text = f"@{manager_name}, пожалуйста, свяжитесь с отделом кибербезопасности. IP-адрес {ip} уязвим. Ваш бывший сотрудник {reporter_name} не активен."
            jira.add_comment(issue, comment_text)
            # Отправка письма руководителю
            email_message_manager = f"Уважаемый {manager_name},\n\nПожалуйста, свяжитесь с отделом кибербезопасности. IP-адрес {ip} уязвим. Ваш бывший сотрудник {reporter_name} не активен."
            send_email(manager_email, email_subject, email_message_manager)
            print(f'Письмо отправлено руководителю {manager_name} для IP-адреса {ip}')

# Разбиваем список IP-адресов на части по 10 адресов
chunk_size = 10
for i in range(0, len(vulnerable_ips), chunk_size):
    ip_chunk = vulnerable_ips[i:i + chunk_size]
    ip_queries = ' OR '.join([f'description ~ "{ip}"' for ip in ip_chunk])
    jql_query = f'({ip_queries}) AND status != "Closed" AND created >= "{cutoff_date_str}"'
    for ip in ip_chunk:
        search_and_comment(jql_query, ip)

print("Готово!")
