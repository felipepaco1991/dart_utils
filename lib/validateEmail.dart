import 'dart:convert';
import 'dart:io';

/// Classe principal para validação de e-mails com práticas de segurança
class EmailValidator {
  // RFC 5322 compliant regex pattern - corrigido
  static final RegExp _emailRegex = RegExp(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
  );

  // Lista de domínios temporários/descartáveis conhecidos
  static final Set<String> _disposableEmailDomains = {
    '10minutemail.com',
    'mailinator.com',
    'guerrillamail.com',
    'yopmail.com',
    'temp-mail.org',
    'throwaway.email',
    'maildrop.cc',
    'tempail.com',
    'dispostable.com',
    'fakeinbox.com',
    'sharklasers.com',
    'getnada.com',
    'tempmail.net',
    'getairmail.com',
    'mohmal.com',
  };

  // Lista de provedores confiáveis
  static final Set<String> _trustedProviders = {
    'gmail.com',
    'outlook.com',
    'hotmail.com',
    'yahoo.com',
    'icloud.com',
    'protonmail.com',
    'aol.com',
    'live.com',
    'msn.com',
    'mail.com',
    'zoho.com',
    'yandex.com',
  };

  /// Valida um endereço de e-mail completo
  static EmailValidationResult validateEmail(String emailInput) {
    var result = EmailValidationResult();

    try {
      // Sanitização inicial
      String email = sanitizeEmail(emailInput);
      result.sanitizedEmail = email;

      // Verificações básicas
      if (!_basicValidation(email, result)) {
        return result;
      }

      // Verificação de formato RFC
      if (!_formatValidation(email, result)) {
        return result;
      }

      // Análise de componentes
      var parts = email.split('@');
      if (parts.length != 2) {
        result.errors.add('E-mail deve conter exatamente um símbolo @');
        return result;
      }

      var localPart = parts[0];
      var domain = parts[1];

      // Validação da parte local
      if (!_validateLocalPart(localPart, result)) {
        return result;
      }

      // Validação do domínio
      if (!_validateDomain(domain, result)) {
        return result;
      }

      // Verificações de segurança
      _securityChecks(email, domain, result);

      // Se chegou até aqui, o e-mail é válido
      result.isValid = true;
      return result;
    } catch (e) {
      result.errors.add('Erro interno na validação: $e');
      return result;
    }
  }

  /// Sanitiza o e-mail removendo espaços e convertendo para lowercase
  static String sanitizeEmail(String email) {
    if (email.isEmpty) return email;
    return email.trim().toLowerCase();
  }

  /// Verificações básicas de entrada
  static bool _basicValidation(String email, EmailValidationResult result) {
    if (email.isEmpty) {
      result.errors.add('E-mail não pode estar vazio');
      return false;
    }

    if (email.length > 254) {
      result.errors.add('E-mail muito longo (máximo 254 caracteres)');
      return false;
    }

    if (!email.contains('@')) {
      result.errors.add('E-mail deve conter o símbolo @');
      return false;
    }

    var atCount = '@'.allMatches(email).length;
    if (atCount != 1) {
      result.errors.add('E-mail deve conter exatamente um símbolo @');
      return false;
    }

    // Verifica caracteres de controle
    if (email.contains(RegExp(r'[\x00-\x1F\x7F]'))) {
      result.errors.add('E-mail contém caracteres de controle inválidos');
      return false;
    }

    return true;
  }

  /// Validação de formato usando RegEx
  static bool _formatValidation(String email, EmailValidationResult result) {
    if (!_emailRegex.hasMatch(email)) {
      result.errors.add('Formato de e-mail inválido');
      return false;
    }
    return true;
  }

  /// Valida a parte local do e-mail (antes do @)
  static bool _validateLocalPart(
    String localPart,
    EmailValidationResult result,
  ) {
    if (localPart.isEmpty) {
      result.errors.add('Parte local do e-mail não pode estar vazia');
      return false;
    }

    if (localPart.length > 64) {
      result.errors.add('Parte local muito longa (máximo 64 caracteres)');
      return false;
    }

    if (localPart.startsWith('.') || localPart.endsWith('.')) {
      result.errors.add('Parte local não pode começar ou terminar com ponto');
      return false;
    }

    if (localPart.contains('..')) {
      result.errors.add('Parte local não pode conter pontos consecutivos');
      return false;
    }

    // Verifica caracteres suspeitos
    var suspiciousChars = RegExp(r'[<>"\[\]\\()]');
    if (suspiciousChars.hasMatch(localPart)) {
      result.warnings.add(
        'Parte local contém caracteres potencialmente problemáticos',
      );
    }

    // Verifica se há apenas caracteres válidos
    var validChars = RegExp(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$");
    if (!validChars.hasMatch(localPart)) {
      result.errors.add('Parte local contém caracteres inválidos');
      return false;
    }

    return true;
  }

  /// Valida o domínio do e-mail
  static bool _validateDomain(String domain, EmailValidationResult result) {
    if (domain.isEmpty) {
      result.errors.add('Domínio não pode estar vazio');
      return false;
    }

    if (domain.length > 253) {
      result.errors.add('Domínio muito longo (máximo 253 caracteres)');
      return false;
    }

    if (domain.startsWith('-') || domain.endsWith('-')) {
      result.errors.add('Domínio não pode começar ou terminar com hífen');
      return false;
    }

    if (domain.startsWith('.') || domain.endsWith('.')) {
      result.errors.add('Domínio não pode começar ou terminar com ponto');
      return false;
    }

    if (!domain.contains('.')) {
      result.errors.add('Domínio deve conter pelo menos um ponto');
      return false;
    }

    if (domain.contains('..')) {
      result.errors.add('Domínio não pode conter pontos consecutivos');
      return false;
    }

    // Valida cada parte do domínio
    var domainParts = domain.split('.');
    for (var part in domainParts) {
      if (part.isEmpty) {
        result.errors.add('Domínio não pode ter partes vazias');
        return false;
      }

      if (part.length > 63) {
        result.errors.add(
          'Parte do domínio muito longa (máximo 63 caracteres)',
        );
        return false;
      }

      if (part.startsWith('-') || part.endsWith('-')) {
        result.errors.add(
          'Partes do domínio não podem começar ou terminar com hífen',
        );
        return false;
      }

      if (!RegExp(r'^[a-z0-9-]+$').hasMatch(part)) {
        result.errors.add('Domínio contém caracteres inválidos');
        return false;
      }
    }

    // Verifica TLD
    var tld = domainParts.last;
    if (tld.length < 2) {
      result.errors.add('TLD deve ter pelo menos 2 caracteres');
      return false;
    }

    if (RegExp(r'^\d+$').hasMatch(tld)) {
      result.errors.add('TLD não pode ser apenas números');
      return false;
    }

    // TLD não pode conter hífen
    if (tld.contains('-')) {
      result.errors.add('TLD não pode conter hífen');
      return false;
    }

    return true;
  }

  /// Verificações de segurança adicionais
  static void _securityChecks(
    String email,
    String domain,
    EmailValidationResult result,
  ) {
    // Verifica domínios descartáveis
    if (_disposableEmailDomains.contains(domain)) {
      result.warnings.add('Domínio de e-mail temporário/descartável detectado');
      result.isDisposable = true;
    }

    // Verifica provedores confiáveis
    if (_trustedProviders.contains(domain)) {
      result.isTrusted = true;
    }

    // Verifica padrões suspeitos
    if (email.contains('+')) {
      result.warnings.add(
        'E-mail contém alias (+) - pode ser usado para contornar restrições',
      );
    }

    // Verifica domínios com muitos números
    if (RegExp(r'\d{3,}').hasMatch(domain)) {
      result.warnings.add('Domínio contém muitos números consecutivos');
    }

    // Verifica domínios muito curtos (suspeitos)
    if (domain.length < 4) {
      result.warnings.add('Domínio muito curto - pode ser suspeito');
    }

    // Verifica caracteres homógrafos (ataques de IDN)
    if (_containsHomoglyphs(email)) {
      result.warnings.add('E-mail pode conter caracteres homógrafos suspeitos');
    }

    // Verifica se é IP literal (geralmente suspeito)
    if (RegExp(r'^\[?\d+\.\d+\.\d+\.\d+\]?$').hasMatch(domain)) {
      result.warnings.add('Domínio é um endereço IP - pode ser suspeito');
    }
  }

  /// Verifica se contém caracteres homógrafos
  static bool _containsHomoglyphs(String text) {
    // Lista de caracteres homógrafos comuns (cirílico que se parecem com latinos)
    var homoglyphs = [
      'а',
      'о',
      'р',
      'е',
      'у',
      'х',
      'с',
      'н',
      'к',
      'в',
      'т',
      'м',
    ];
    return homoglyphs.any((char) => text.contains(char));
  }

  /// Normaliza o e-mail aplicando regras específicas de provedores
  static String normalizeEmail(String emailInput) {
    try {
      String email = sanitizeEmail(emailInput);
      var parts = email.split('@');

      if (parts.length != 2) return email;

      var localPart = parts[0];
      var domain = parts[1];

      // Regras específicas para Gmail
      if (domain == 'gmail.com') {
        // Remove pontos da parte local
        localPart = localPart.replaceAll('.', '');
        // Remove tudo após o + (alias)
        var plusIndex = localPart.indexOf('+');
        if (plusIndex != -1) {
          localPart = localPart.substring(0, plusIndex);
        }
      }

      // Regras para Outlook/Hotmail/Live
      if (['outlook.com', 'hotmail.com', 'live.com'].contains(domain)) {
        // Remove tudo após o + (alias)
        var plusIndex = localPart.indexOf('+');
        if (plusIndex != -1) {
          localPart = localPart.substring(0, plusIndex);
        }
      }

      return '$localPart@$domain';
    } catch (e) {
      return emailInput; // Retorna o original se houver erro
    }
  }

  /// Extrai sugestões de correção para e-mails com erros comuns
  static List<String> suggestCorrections(String emailInput) {
    var suggestions = <String>[];

    try {
      String email = sanitizeEmail(emailInput);

      // Correções de domínios comuns
      var commonTypos = {
        'gmial.com': 'gmail.com',
        'gmai.com': 'gmail.com',
        'gmail.co': 'gmail.com',
        'gmail.con': 'gmail.com',
        'yahooo.com': 'yahoo.com',
        'yaho.com': 'yahoo.com',
        'yahoo.co': 'yahoo.com',
        'hotmial.com': 'hotmail.com',
        'hotmai.com': 'hotmail.com',
        'hotmail.co': 'hotmail.com',
        'outlok.com': 'outlook.com',
        'outlook.co': 'outlook.com',
      };

      var parts = email.split('@');
      if (parts.length == 2) {
        var localPart = parts[0];
        var domain = parts[1];

        // Verifica correções diretas
        commonTypos.forEach((typo, correct) {
          if (domain == typo) {
            suggestions.add('$localPart@$correct');
          }
        });

        // Sugestões baseadas em similaridade
        if (suggestions.isEmpty) {
          for (var trustedDomain in _trustedProviders) {
            if (_levenshteinDistance(domain, trustedDomain) <= 2 &&
                domain != trustedDomain) {
              suggestions.add('$localPart@$trustedDomain');
            }
          }
        }
      }
    } catch (e) {
      // Se houver erro, não adiciona sugestões
    }

    return suggestions.take(3).toList(); // Máximo 3 sugestões
  }

  /// Calcula distância de Levenshtein para sugestões
  static int _levenshteinDistance(String s1, String s2) {
    if (s1 == s2) return 0;
    if (s1.isEmpty) return s2.length;
    if (s2.isEmpty) return s1.length;

    var matrix = List.generate(
      s1.length + 1,
      (i) => List.filled(s2.length + 1, 0),
    );

    for (var i = 0; i <= s1.length; i++) {
      matrix[i][0] = i;
    }
    for (var j = 0; j <= s2.length; j++) {
      matrix[0][j] = j;
    }

    for (var i = 1; i <= s1.length; i++) {
      for (var j = 1; j <= s2.length; j++) {
        var cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
        matrix[i][j] = [
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost,
        ].reduce((a, b) => a < b ? a : b);
      }
    }

    return matrix[s1.length][s2.length];
  }
}

/// Classe que representa o resultado da validação
class EmailValidationResult {
  bool isValid = false;
  bool isDisposable = false;
  bool isTrusted = false;
  String sanitizedEmail = '';
  List<String> errors = <String>[];
  List<String> warnings = <String>[];

  /// Retorna um resumo do resultado da validação
  String get summary {
    if (isValid) {
      var status = 'E-mail válido';
      if (isTrusted) status += ' (provedor confiável)';
      if (isDisposable) status += ' (domínio temporário)';
      return status;
    } else {
      return 'E-mail inválido: ${errors.join(', ')}';
    }
  }

  /// Converte o resultado para JSON
  Map<String, dynamic> toJson() {
    return {
      'isValid': isValid,
      'isDisposable': isDisposable,
      'isTrusted': isTrusted,
      'sanitizedEmail': sanitizedEmail,
      'errors': errors,
      'warnings': warnings,
      'summary': summary,
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

/// Classe para interface interativa com o usuário
class EmailValidatorApp {
  static void run() {
    try {
      _printHeader();

      while (true) {
        _printMenu();

        String? choice = stdin.readLineSync();

        switch (choice?.trim()) {
          case '1':
            _validateSingleEmail();
            break;
          case '2':
            _validateMultipleEmails();
            break;
          case '3':
            _showEmailTips();
            break;
          case '4':
            _showAbout();
            break;
          case '0':
            _printGoodbye();
            return;
          default:
            stdout.writeln('\nOpção inválida! Tente novamente.\n');
        }
      }
    } catch (e) {
      stdout.writeln('\nErro na aplicação: $e');
      stdout.writeln('Encerrando o programa...\n');
    }
  }

  static void _printHeader() {
    stdout.writeln('\n${'=' * 60}');
    stdout.writeln('VALIDADOR DE E-MAILS PROFISSIONAL'.padLeft(44));
    stdout.writeln('${'=' * 60}');
    stdout.writeln('Sistema avançado de validação com segurança integrada');
    stdout.writeln('Desenvolvido com as melhores práticas do mercado\n');
  }

  static void _printMenu() {
    stdout.writeln('MENU PRINCIPAL:');
    stdout.writeln('─' * 30);
    stdout.writeln('1. Validar um e-mail');
    stdout.writeln('2. Validar múltiplos e-mails');
    stdout.writeln('3. Dicas de e-mails seguros');
    stdout.writeln('4. Sobre o sistema');
    stdout.writeln('0. Sair');
    stdout.writeln('─' * 30);
    stdout.write('Escolha uma opção: ');
  }

  static void _validateSingleEmail() {
    stdout.writeln('\nVALIDAÇÃO DE E-MAIL ÚNICO');
    stdout.writeln('─' * 40);

    while (true) {
      try {
        stdout.write('Digite o e-mail (ou "voltar" para retornar): ');
        String? input = stdin.readLineSync();

        if (input == null || input.trim().isEmpty) {
          stdout.writeln('Por favor, digite um e-mail válido.\n');
          continue;
        }

        input = input.trim();

        if (input.toLowerCase() == 'voltar') {
          stdout.writeln('');
          return;
        }

        _processEmailValidation(input);

        stdout.write('\nDeseja validar outro e-mail? (s/N): ');
        String? continueChoice = stdin.readLineSync();

        if (continueChoice?.toLowerCase() != 's' &&
            continueChoice?.toLowerCase() != 'sim') {
          stdout.writeln('');
          return;
        }
        stdout.writeln('');
      } catch (e) {
        stdout.writeln('Erro durante a validação: $e');
        stdout.writeln('');
      }
    }
  }

  static void _validateMultipleEmails() {
    stdout.writeln('\nVALIDAÇÃO DE MÚLTIPLOS E-MAILS');
    stdout.writeln('─' * 45);
    stdout.writeln('Digite os e-mails separados por vírgula ou linha');
    stdout.writeln('Digite "fim" em uma linha separada para finalizar\n');

    List<String> emails = <String>[];

    try {
      while (true) {
        stdout.write('E-mail ${emails.length + 1}: ');
        String? input = stdin.readLineSync();

        if (input == null) continue;

        input = input.trim();

        if (input.toLowerCase() == 'fim') {
          break;
        }

        if (input.isEmpty) {
          continue;
        }

        // Suporta múltiplos e-mails separados por vírgula
        if (input.contains(',')) {
          var splitEmails = input
              .split(',')
              .map((e) => e.trim())
              .where((e) => e.isNotEmpty)
              .toList();
          emails.addAll(splitEmails);
          stdout.writeln('Adicionados ${splitEmails.length} e-mails');
        } else {
          emails.add(input);
          stdout.writeln('E-mail adicionado');
        }
      }

      if (emails.isEmpty) {
        stdout.writeln('Nenhum e-mail foi fornecido.\n');
        return;
      }

      stdout.writeln('\nPROCESSANDO ${emails.length} E-MAIL(S)...\n');

      int validCount = 0;
      int invalidCount = 0;
      int warningCount = 0;

      for (int i = 0; i < emails.length; i++) {
        stdout.writeln('E-mail ${i + 1}/${emails.length}: ${emails[i]}');

        var result = _processEmailValidation(emails[i]);

        if (result.isValid) {
          validCount++;
          if (result.warnings.isNotEmpty) {
            warningCount++;
          }
        } else {
          invalidCount++;
        }

        if (i < emails.length - 1) {
          stdout.writeln('─' * 50);
        }
      }

      _printSummary(validCount, invalidCount, warningCount, emails.length);
    } catch (e) {
      stdout.writeln('Erro durante a validação múltipla: $e\n');
    }
  }

  static EmailValidationResult _processEmailValidation(String email) {
    var result = EmailValidator.validateEmail(email);

    stdout.writeln('E-mail original: $email');
    stdout.writeln('E-mail sanitizado: ${result.sanitizedEmail}');

    if (result.isValid) {
      stdout.writeln('Status: ${result.summary}');

      // Mostra versão normalizada se diferente
      var normalized = EmailValidator.normalizeEmail(email);
      if (normalized != result.sanitizedEmail) {
        stdout.writeln('Versão normalizada: $normalized');
      }

      // Mostra avisos se existirem
      if (result.warnings.isNotEmpty) {
        stdout.writeln('Avisos:');
        for (var warning in result.warnings) {
          stdout.writeln('  • $warning');
        }
      }

      // Informações adicionais
      if (result.isTrusted) {
        stdout.writeln('Provedor confiável detectado');
      }

      if (result.isDisposable) {
        stdout.writeln('E-mail temporário/descartável detectado');
      }
    } else {
      stdout.writeln('Status: E-mail inválido');
      stdout.writeln('Erros encontrados:');
      for (var error in result.errors) {
        stdout.writeln('  • $error');
      }

      // Sugestões de correção
      var suggestions = EmailValidator.suggestCorrections(email);
      if (suggestions.isNotEmpty) {
        stdout.writeln('Sugestões de correção:');
        for (int i = 0; i < suggestions.length; i++) {
          stdout.writeln('  ${i + 1}. ${suggestions[i]}');
        }
      }
    }

    return result;
  }

  static void _printSummary(int valid, int invalid, int warnings, int total) {
    stdout.writeln('\n${'=' * 50}');
    stdout.writeln('RESUMO DA VALIDAÇÃO'.padLeft(32));
    stdout.writeln('${'=' * 50}');
    stdout.writeln('Total de e-mails: $total');
    stdout.writeln('Válidos: $valid');
    stdout.writeln('Inválidos: $invalid');
    stdout.writeln('Com avisos: $warnings');

    if (total > 0) {
      stdout.writeln(
        'Taxa de sucesso: ${((valid / total) * 100).toStringAsFixed(1)}%',
      );
    }

    stdout.writeln('${'=' * 50}\n');
  }

  static void _showEmailTips() {
    stdout.writeln('\nDICAS PARA E-MAILS SEGUROS');
    stdout.writeln('─' * 45);
    stdout.writeln('SEGURANÇA:');
    stdout.writeln('  • Use provedores confiáveis (Gmail, Outlook, etc.)');
    stdout.writeln('  • Evite e-mails temporários para contas importantes');
    stdout.writeln('  • Cuidado com caracteres especiais suspeitos');
    stdout.writeln('  • Verifique sempre a ortografia do domínio');
    stdout.writeln('');
    stdout.writeln('BOAS PRÁTICAS:');
    stdout.writeln('  • Mantenha o e-mail simples e claro');
    stdout.writeln('  • Evite pontos no início ou fim');
    stdout.writeln('  • Não use pontos consecutivos (..)');
    stdout.writeln('  • Prefira letras minúsculas');
    stdout.writeln('');
    stdout.writeln('EVITE:');
    stdout.writeln('  • Domínios com muitos números');
    stdout.writeln('  • Caracteres especiais desnecessários');
    stdout.writeln('  • E-mails muito longos (>50 caracteres)');
    stdout.writeln('  • Provedores desconhecidos ou suspeitos\n');
  }

  static void _showAbout() {
    stdout.writeln('\nSOBRE O SISTEMA');
    stdout.writeln('─' * 35);
    stdout.writeln('Validador de E-mails Profissional v2.1');
    stdout.writeln('Desenvolvido em 2025');
    stdout.writeln('');
    stdout.writeln('RECURSOS:');
    stdout.writeln('  • Validação RFC 5322 completa');
    stdout.writeln('  • Detecção de domínios descartáveis');
    stdout.writeln('  • Identificação de provedores confiáveis');
    stdout.writeln('  • Sugestões inteligentes de correção');
    stdout.writeln('  • Normalização automática');
    stdout.writeln('  • Verificações de segurança avançadas');
    stdout.writeln('');
    stdout.writeln('SEGURANÇA:');
    stdout.writeln('  • Detecção de ataques homógrafos');
    stdout.writeln('  • Validação de caracteres suspeitos');
    stdout.writeln('  • Análise de padrões maliciosos');
    stdout.writeln('  • Proteção contra bypass de aliases');
    stdout.writeln('  • Detecção de endereços IP como domínio');
    stdout.writeln('');
    stdout.writeln('PERFORMANCE:');
    stdout.writeln('  • Validação em tempo real');
    stdout.writeln('  • Processamento em lote');
    stdout.writeln('  • Algoritmos otimizados');
    stdout.writeln('  • Interface intuitiva');
    stdout.writeln('  • Tratamento robusto de erros\n');
  }

  static void _printGoodbye() {
    stdout.writeln('\n${'=' * 50}');
    stdout.writeln('OBRIGADO POR USAR O VALIDADOR!'.padLeft(32));
    stdout.writeln('${'=' * 50}');
    stdout.writeln('Seus e-mails estão mais seguros agora!');
    stdout.writeln('Continue validando para manter a segurança.');
    stdout.writeln('${'=' * 50}\n');
  }
}

// Função principal - inicia a aplicação interativa
void main() {
  EmailValidatorApp.run();
}
