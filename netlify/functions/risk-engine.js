/**
 * UNIFIED RISK ENGINE
 * Централизованная система оценки рисков для URL и файлов
 */

/**
 * CONFIGURATION
 */
const RISK_CONFIG = {
  // Веса для различных сигналов (0-100)
  WEIGHTS: {
    // URL специфичные
    GOOGLE_SAFE_BROWSING_DANGER: 50,
    VIRUSTOTAL_URL_DANGER: 40,
    VIRUSTOTAL_URL_SUSPICIOUS: 20,
    DOMAIN_AGE_CRITICAL: 35,  // < 7 дней
    DOMAIN_AGE_HIGH: 25,      // < 30 дней
    DOMAIN_AGE_MEDIUM: 15,    // < 90 дней
    
    // FILE специфичные
    VIRUSTOTAL_FILE_BASE: 60,
    VIRUSTOTAL_FILE_PER_DETECTION: 2, // Дополнительно за каждую детекцию
    EXECUTABLE_EXTENSION: 15,
    SUSPICIOUS_MIMETYPE: 10,
    EXTENSION_MISMATCH: 20,
    HIGH_ENTROPY: 10,
    
    // Бонусы за корреляцию
    MULTIPLE_CRITICAL_FLAGS: 15,
    UNCERTAINTY_PENALTY: 10,
  },
  
  // Пороги уровней риска
  THRESHOLDS: {
    CRITICAL: 80,
    DANGEROUS: 60,
    SUSPICIOUS: 35,
    LOW_RISK: 15,
    SAFE: 0,
  },
  
  // Пороги уверенности
  CONFIDENCE_THRESHOLDS: {
    HIGH: 90,
    MEDIUM: 60,
    LOW: 0,
  },
};

/**
 * RISK LEVEL ENUM
 */
const RiskLevel = {
  CRITICAL: 'critical',
  DANGEROUS: 'dangerous',
  SUSPICIOUS: 'suspicious',
  LOW_RISK: 'low-risk',
  SAFE: 'safe',
};

/**
 * CONFIDENCE LEVEL ENUM
 */
const ConfidenceLevel = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

/**
 * SIGNAL STATUS ENUM
 */
const SignalStatus = {
  SAFE: 'safe',
  LOW_RISK: 'low-risk',
  SUSPICIOUS: 'suspicious',
  DANGER: 'danger',
  CRITICAL: 'critical',
  ERROR: 'error',
  UNAVAILABLE: 'unavailable',
  PENDING: 'pending',
};

/**
 * INPUT SIGNAL SCHEMAS
 */

/**
 * Нормализованная структура для URL проверок
 * @typedef {Object} URLSignals
 * @property {string} type - 'url'
 * @property {string} url - Проверяемый URL
 * @property {string} domain - Извлеченный домен
 * @property {Object} googleSafeBrowsing - Результат Google Safe Browsing
 * @property {string} googleSafeBrowsing.status - safe|danger|error|unavailable
 * @property {string} [googleSafeBrowsing.details] - Дополнительная информация
 * @property {Object} virusTotal - Результат VirusTotal
 * @property {string} virusTotal.status - safe|suspicious|danger|pending|error|unavailable
 * @property {number} [virusTotal.score] - Количество детекций
 * @property {string} [virusTotal.details] - Дополнительная информация
 * @property {Object} whois - Информация о домене
 * @property {string} whois.status - ok|error|unknown
 * @property {number} [whois.domainAgeDays] - Возраст домена в днях
 * @property {string} [whois.risk] - critical|high|medium|low
 * @property {Object} [metadata] - Дополнительные метаданные
 */

/**
 * Нормализованная структура для FILE проверок
 * @typedef {Object} FileSignals
 * @property {string} type - 'file'
 * @property {string} filename - Имя файла
 * @property {number} fileSize - Размер в байтах
 * @property {string} mimeType - MIME тип
 * @property {string} [fileHash] - SHA256 хеш
 * @property {Object} virusTotal - Результат VirusTotal
 * @property {string} virusTotal.status - safe|low-risk|suspicious|danger|pending|error|unavailable
 * @property {number} [virusTotal.positives] - Количество положительных детекций
 * @property {number} [virusTotal.total] - Общее количество антивирусов
 * @property {number} [virusTotal.percentage] - Процент детекций
 * @property {Object} staticAnalysis - Статический анализ файла
 * @property {string} staticAnalysis.fileExtension - Расширение файла
 * @property {boolean} staticAnalysis.hasExecutableExtension - Исполняемое расширение
 * @property {boolean} staticAnalysis.hasSuspiciousMimeType - Подозрительный MIME
 * @property {boolean} staticAnalysis.extensionMismatch - Несоответствие расширения
 * @property {number} staticAnalysis.entropy - Энтропия (0-8)
 * @property {boolean} staticAnalysis.highEntropy - Высокая энтропия
 * @property {string} staticAnalysis.fileSignature - Сигнатура файла
 * @property {Object} [metadata] - Дополнительные метаданные
 */

/**
 * OUTPUT SCHEMA
 * @typedef {Object} RiskAssessment
 * @property {Object} risk - Оценка риска
 * @property {number} risk.score - Оценка 0-100
 * @property {string} risk.level - critical|dangerous|suspicious|low-risk|safe
 * @property {string} risk.confidence - high|medium|low
 * @property {number} risk.confidenceScore - Процент уверенности 0-100
 * @property {Object} analysis - Детальный анализ
 * @property {Array<Object>} analysis.signals - Использованные сигналы
 * @property {Array<string>} analysis.criticalFlags - Критические флаги
 * @property {Array<string>} analysis.warnings - Предупреждения
 * @property {string} analysis.primaryReason - Главная причина оценки
 * @property {Object} recommendations - Рекомендации
 * @property {string} recommendations.user - Для обычных пользователей
 * @property {string} recommendations.business - Для бизнеса
 * @property {string} recommendations.technical - Для технических специалистов
 * @property {string} summary - Краткое резюме
 * @property {Object} context - Контекст для AI (опционально)
 */

/**
 * MAIN RISK ENGINE CLASS
 */
class RiskEngine {
  /**
   * Анализирует риски на основе входных сигналов
   * @param {URLSignals|FileSignals} signals - Нормализованные сигналы
   * @returns {RiskAssessment} Оценка рисков
   */
  static assess(signals) {
    if (!signals || !signals.type) {
      throw new Error('Invalid signals: type is required');
    }

    if (signals.type === 'url') {
      return this.assessURL(signals);
    } else if (signals.type === 'file') {
      return this.assessFile(signals);
    } else {
      throw new Error(`Unknown signal type: ${signals.type}`);
    }
  }

  /**
   * Оценка рисков для URL
   * @private
   */
  static assessURL(signals) {
    const activeSignals = [];
    const criticalFlags = [];
    const warnings = [];
    let score = 0;

    // Google Safe Browsing
    if (signals.googleSafeBrowsing?.status === SignalStatus.DANGER) {
      score += RISK_CONFIG.WEIGHTS.GOOGLE_SAFE_BROWSING_DANGER;
      criticalFlags.push('google_safe_browsing_threat');
      activeSignals.push({
        source: 'Google Safe Browsing',
        status: 'danger',
        weight: RISK_CONFIG.WEIGHTS.GOOGLE_SAFE_BROWSING_DANGER,
        details: signals.googleSafeBrowsing.details,
      });
    } else if (signals.googleSafeBrowsing?.status === SignalStatus.SAFE) {
      activeSignals.push({
        source: 'Google Safe Browsing',
        status: 'safe',
        weight: 0,
      });
    }

    // VirusTotal URL
    if (signals.virusTotal?.status === SignalStatus.DANGER) {
      const vtScore = signals.virusTotal.score || 1;
      const weight = RISK_CONFIG.WEIGHTS.VIRUSTOTAL_URL_DANGER + Math.min(vtScore * 2, 10);
      score += weight;
      criticalFlags.push('virustotal_malicious');
      activeSignals.push({
        source: 'VirusTotal',
        status: 'danger',
        weight: weight,
        details: signals.virusTotal.details,
      });
    } else if (signals.virusTotal?.status === SignalStatus.SUSPICIOUS) {
      score += RISK_CONFIG.WEIGHTS.VIRUSTOTAL_URL_SUSPICIOUS;
      warnings.push('virustotal_suspicious');
      activeSignals.push({
        source: 'VirusTotal',
        status: 'suspicious',
        weight: RISK_CONFIG.WEIGHTS.VIRUSTOTAL_URL_SUSPICIOUS,
      });
    } else if (signals.virusTotal?.status === SignalStatus.SAFE) {
      activeSignals.push({
        source: 'VirusTotal',
        status: 'safe',
        weight: 0,
      });
    }

    // WHOIS / Domain Age
    if (signals.whois?.status === 'ok' && signals.whois.domainAgeDays !== undefined) {
      const ageDays = signals.whois.domainAgeDays;
      
      if (ageDays < 7) {
        score += RISK_CONFIG.WEIGHTS.DOMAIN_AGE_CRITICAL;
        criticalFlags.push('domain_extremely_new');
        activeSignals.push({
          source: 'WHOIS',
          status: 'critical',
          weight: RISK_CONFIG.WEIGHTS.DOMAIN_AGE_CRITICAL,
          details: `Domain only ${ageDays} days old`,
        });
      } else if (ageDays < 30) {
        score += RISK_CONFIG.WEIGHTS.DOMAIN_AGE_HIGH;
        warnings.push('domain_very_new');
        activeSignals.push({
          source: 'WHOIS',
          status: 'high-risk',
          weight: RISK_CONFIG.WEIGHTS.DOMAIN_AGE_HIGH,
          details: `Domain ${ageDays} days old`,
        });
      } else if (ageDays < 90) {
        score += RISK_CONFIG.WEIGHTS.DOMAIN_AGE_MEDIUM;
        warnings.push('domain_new');
        activeSignals.push({
          source: 'WHOIS',
          status: 'medium-risk',
          weight: RISK_CONFIG.WEIGHTS.DOMAIN_AGE_MEDIUM,
          details: `Domain ${ageDays} days old`,
        });
      } else {
        activeSignals.push({
          source: 'WHOIS',
          status: 'safe',
          weight: 0,
          details: `Domain ${ageDays} days old (established)`,
        });
      }
    }

    // Корреляция критических флагов
    if (criticalFlags.length >= 2) {
      score += RISK_CONFIG.WEIGHTS.MULTIPLE_CRITICAL_FLAGS;
      warnings.push('multiple_threat_sources');
    }

    // Штраф за недостаток данных
    if (activeSignals.length === 0) {
      score += RISK_CONFIG.WEIGHTS.UNCERTAINTY_PENALTY * 5; // 50 баллов
      warnings.push('insufficient_data');
    } else if (activeSignals.length === 1) {
      score += RISK_CONFIG.WEIGHTS.UNCERTAINTY_PENALTY;
      warnings.push('limited_data');
    }

    const finalScore = Math.min(Math.round(score), 100);
    const riskLevel = this.scoreToLevel(finalScore);
    const confidence = this.calculateConfidenceURL(signals, activeSignals.length);
    const primaryReason = this.determinePrimaryReason(activeSignals, criticalFlags, warnings);

    return {
      risk: {
        score: finalScore,
        level: riskLevel,
        confidence: confidence.level,
        confidenceScore: confidence.score,
      },
      analysis: {
        signals: activeSignals,
        criticalFlags,
        warnings,
        primaryReason,
        assessmentType: 'url',
      },
      recommendations: this.generateRecommendations(riskLevel, confidence.level, 'url'),
      summary: this.generateSummary(riskLevel, confidence.level, primaryReason, 'url'),
      context: this.buildAIContext(signals, finalScore, riskLevel, activeSignals),
    };
  }

  /**
   * Оценка рисков для файла
   * @private
   */
  static assessFile(signals) {
    const activeSignals = [];
    const criticalFlags = [];
    const warnings = [];
    let score = 0;

    // VirusTotal File
    if (signals.virusTotal?.status === SignalStatus.DANGER) {
      const percentage = signals.virusTotal.percentage || 0;
      const baseWeight = RISK_CONFIG.WEIGHTS.VIRUSTOTAL_FILE_BASE;
      const additionalWeight = Math.min(percentage, 30);
      const totalWeight = baseWeight + additionalWeight;
      
      score += totalWeight;
      criticalFlags.push('virustotal_malware_detected');
      activeSignals.push({
        source: 'VirusTotal',
        status: 'danger',
        weight: totalWeight,
        details: `${signals.virusTotal.positives}/${signals.virusTotal.total} detections (${percentage}%)`,
      });
    } else if (signals.virusTotal?.status === SignalStatus.SUSPICIOUS) {
      const percentage = signals.virusTotal.percentage || 0;
      const weight = 40 + Math.min(percentage / 2, 15);
      score += weight;
      warnings.push('virustotal_suspicious_detections');
      activeSignals.push({
        source: 'VirusTotal',
        status: 'suspicious',
        weight: Math.round(weight),
        details: `${signals.virusTotal.positives}/${signals.virusTotal.total} detections`,
      });
    } else if (signals.virusTotal?.status === SignalStatus.LOW_RISK) {
      score += 20;
      warnings.push('virustotal_few_detections');
      activeSignals.push({
        source: 'VirusTotal',
        status: 'low-risk',
        weight: 20,
        details: signals.virusTotal.details,
      });
    } else if (signals.virusTotal?.status === SignalStatus.SAFE) {
      activeSignals.push({
        source: 'VirusTotal',
        status: 'safe',
        weight: 0,
      });
    }

    // Static Analysis
    if (signals.staticAnalysis) {
      const sa = signals.staticAnalysis;

      // Исполняемое расширение
      if (sa.hasExecutableExtension) {
        score += RISK_CONFIG.WEIGHTS.EXECUTABLE_EXTENSION;
        warnings.push('executable_file_type');
        activeSignals.push({
          source: 'Static Analysis',
          status: 'warning',
          weight: RISK_CONFIG.WEIGHTS.EXECUTABLE_EXTENSION,
          details: `Executable extension: ${sa.fileExtension}`,
        });
      }

      // Подозрительный MIME
      if (sa.hasSuspiciousMimeType) {
        score += RISK_CONFIG.WEIGHTS.SUSPICIOUS_MIMETYPE;
        warnings.push('suspicious_mime_type');
        activeSignals.push({
          source: 'Static Analysis',
          status: 'warning',
          weight: RISK_CONFIG.WEIGHTS.SUSPICIOUS_MIMETYPE,
          details: 'Suspicious MIME type detected',
        });
      }

      // Несоответствие расширения - КРИТИЧНО
      if (sa.extensionMismatch) {
        score += RISK_CONFIG.WEIGHTS.EXTENSION_MISMATCH;
        criticalFlags.push('extension_mismatch');
        activeSignals.push({
          source: 'Static Analysis',
          status: 'danger',
          weight: RISK_CONFIG.WEIGHTS.EXTENSION_MISMATCH,
          details: `Extension ${sa.fileExtension} doesn't match file signature ${sa.fileSignature}`,
        });
      }

      // Высокая энтропия
      if (sa.highEntropy) {
        score += RISK_CONFIG.WEIGHTS.HIGH_ENTROPY;
        warnings.push('high_entropy_detected');
        activeSignals.push({
          source: 'Static Analysis',
          status: 'warning',
          weight: RISK_CONFIG.WEIGHTS.HIGH_ENTROPY,
          details: `High entropy: ${sa.entropy.toFixed(2)} (possible encryption/packing)`,
        });
      }
    }

    // Корреляция критических флагов
    if (criticalFlags.length >= 2) {
      score += RISK_CONFIG.WEIGHTS.MULTIPLE_CRITICAL_FLAGS;
      warnings.push('multiple_threat_indicators');
    }

    const finalScore = Math.min(Math.round(score), 100);
    const riskLevel = this.scoreToLevel(finalScore);
    const confidence = this.calculateConfidenceFile(signals, activeSignals.length);
    const primaryReason = this.determinePrimaryReason(activeSignals, criticalFlags, warnings);

    return {
      risk: {
        score: finalScore,
        level: riskLevel,
        confidence: confidence.level,
        confidenceScore: confidence.score,
      },
      analysis: {
        signals: activeSignals,
        criticalFlags,
        warnings,
        primaryReason,
        assessmentType: 'file',
      },
      recommendations: this.generateRecommendations(riskLevel, confidence.level, 'file'),
      summary: this.generateSummary(riskLevel, confidence.level, primaryReason, 'file'),
      context: this.buildAIContext(signals, finalScore, riskLevel, activeSignals),
    };
  }

  /**
   * Преобразование оценки в уровень риска
   * @private
   */
  static scoreToLevel(score) {
    if (score >= RISK_CONFIG.THRESHOLDS.CRITICAL) return RiskLevel.CRITICAL;
    if (score >= RISK_CONFIG.THRESHOLDS.DANGEROUS) return RiskLevel.DANGEROUS;
    if (score >= RISK_CONFIG.THRESHOLDS.SUSPICIOUS) return RiskLevel.SUSPICIOUS;
    if (score >= RISK_CONFIG.THRESHOLDS.LOW_RISK) return RiskLevel.LOW_RISK;
    return RiskLevel.SAFE;
  }

  /**
   * Расчет уверенности для URL
   * @private
   */
  static calculateConfidenceURL(signals, activeSignalsCount) {
    let confidenceScore = 0;

    // Google Safe Browsing доступен
    if ([SignalStatus.SAFE, SignalStatus.DANGER].includes(signals.googleSafeBrowsing?.status)) {
      confidenceScore += 35;
    }

    // VirusTotal доступен
    if ([SignalStatus.SAFE, SignalStatus.DANGER, SignalStatus.SUSPICIOUS].includes(signals.virusTotal?.status)) {
      confidenceScore += 35;
    }

    // WHOIS доступен
    if (signals.whois?.status === 'ok') {
      confidenceScore += 30;
    }

    return {
      score: confidenceScore,
      level: this.scoreToConfidenceLevel(confidenceScore),
    };
  }

  /**
   * Расчет уверенности для файла
   * @private
   */
  static calculateConfidenceFile(signals, activeSignalsCount) {
    let confidenceScore = 0;

    // VirusTotal доступен
    if ([SignalStatus.SAFE, SignalStatus.DANGER, SignalStatus.SUSPICIOUS, SignalStatus.LOW_RISK].includes(signals.virusTotal?.status)) {
      confidenceScore += 70;
    }

    // Статический анализ выполнен
    if (signals.staticAnalysis) {
      confidenceScore += 30;
    }

    return {
      score: confidenceScore,
      level: this.scoreToConfidenceLevel(confidenceScore),
    };
  }

  /**
   * Преобразование оценки уверенности в уровень
   * @private
   */
  static scoreToConfidenceLevel(score) {
    if (score >= RISK_CONFIG.CONFIDENCE_THRESHOLDS.HIGH) return ConfidenceLevel.HIGH;
    if (score >= RISK_CONFIG.CONFIDENCE_THRESHOLDS.MEDIUM) return ConfidenceLevel.MEDIUM;
    return ConfidenceLevel.LOW;
  }

  /**
   * Определение главной причины оценки
   * @private
   */
  static determinePrimaryReason(activeSignals, criticalFlags, warnings) {
    if (criticalFlags.length > 0) {
      const flagMap = {
        'google_safe_browsing_threat': 'Flagged by Google Safe Browsing',
        'virustotal_malicious': 'Multiple antivirus detections',
        'virustotal_malware_detected': 'Malware detected by antivirus engines',
        'domain_extremely_new': 'Extremely new domain (phishing indicator)',
        'extension_mismatch': 'File extension doesn\'t match actual file type',
      };
      return flagMap[criticalFlags[0]] || 'Critical security threat detected';
    }

    if (warnings.length > 0) {
      const warningMap = {
        'virustotal_suspicious': 'Suspicious activity detected',
        'domain_very_new': 'Very new domain registration',
        'domain_new': 'Recently registered domain',
        'executable_file_type': 'Executable file type',
        'high_entropy_detected': 'File appears to be encrypted or packed',
        'insufficient_data': 'Unable to verify safety',
      };
      return warningMap[warnings[0]] || 'Suspicious indicators present';
    }

    return 'No significant threats detected';
  }

  /**
   * Генерация рекомендаций
   * @private
   */
  static generateRecommendations(riskLevel, confidence, type) {
    const lowConfidenceNote = confidence === ConfidenceLevel.LOW
      ? ' Рекомендуется дополнительная проверка из-за ограниченных данных.'
      : '';

    const typeSpecific = type === 'url' ? 'ссылку' : 'файл';
    const actionUrl = type === 'url' ? 'открывайте' : 'открывайте';
    const actionFile = type === 'file' ? 'запускайте' : 'открывайте';

    const recommendations = {
      [RiskLevel.CRITICAL]: {
        user: `⛔ НЕ ${type === 'url' ? 'ОТКРЫВАЙТЕ' : 'ЗАПУСКАЙТЕ'} эту ${typeSpecific}. Крайне высокая вероятность ${type === 'url' ? 'фишинга или вредоносного сайта' : 'вредоносного ПО'}.${lowConfidenceNote}`,
        business: `🚫 Немедленно заблокировать. ${type === 'url' ? 'Добавить в blacklist сети.' : 'Поместить в карантин.'} Уведомить сотрудников о угрозе.`,
        technical: `Провести детальный анализ, ${type === 'url' ? 'заблокировать на уровне DNS/firewall' : 'выполнить sandbox анализ'}, проверить логи на компрометацию, обновить IoC.`,
      },
      [RiskLevel.DANGEROUS]: {
        user: `⛔ НЕ ${actionFile.toUpperCase()} эту ${typeSpecific}. Обнаружены признаки ${type === 'url' ? 'вредоносной активности' : 'вредоносного ПО'}.${lowConfidenceNote}`,
        business: `🚫 Заблокировать доступ. Требуется расследование security team. ${type === 'url' ? 'Мониторить похожие домены.' : 'Провести проверку систем.'}`,
        technical: `${type === 'url' ? 'Добавить в watchlist, проверить репутацию домена' : 'Sandbox анализ, проверка IoC'}, анализ трафика, обновление правил детектирования.`,
      },
      [RiskLevel.SUSPICIOUS]: {
        user: `⚠️ Будьте крайне осторожны. ${type === 'url' ? 'Не вводите личные данные и пароли.' : 'Не запускайте на рабочем компьютере.'}${lowConfidenceNote}`,
        business: `⚠️ Мониторинг активности. ${type === 'url' ? 'Предупредить пользователей.' : 'Дополнительная проверка перед использованием.'}`,
        technical: `${type === 'url' ? 'Проверить SSL сертификат, WHOIS' : 'Провести статический анализ'}, добавить в watchlist, настроить логирование.`,
      },
      [RiskLevel.LOW_RISK]: {
        user: `⚠️ Вероятно безопасно, но проявите осторожность. ${type === 'url' ? 'Убедитесь в правильности адреса.' : 'Убедитесь в источнике файла.'}${lowConfidenceNote}`,
        business: `✓ Минимальный риск. Стандартный мониторинг.`,
        technical: `Базовое логирование, периодическая перепроверка.`,
      },
      [RiskLevel.SAFE]: {
        user: `✅ ${type === 'url' ? 'Ссылка' : 'Файл'} выглядит безопасной, но всегда ${type === 'url' ? 'проверяйте URL перед вводом данных' : 'проверяйте источник файла'}.${lowConfidenceNote}`,
        business: `✅ Дополнительных действий не требуется. Продолжить стандартный мониторинг.`,
        technical: `Обычные процедуры мониторинга безопасности.`,
      },
    };

    return recommendations[riskLevel] || recommendations[RiskLevel.SAFE];
  }

  /**
   * Генерация краткого резюме
   * @private
   */
  static generateSummary(riskLevel, confidence, primaryReason, type) {
    const confidenceText = confidence === ConfidenceLevel.LOW ? ' (ограниченные данные)' : '';
    const typeText = type === 'url' ? 'URL' : 'Файл';

    const summaries = {
      [RiskLevel.CRITICAL]: `КРИТИЧЕСКИЙ РИСК: ${primaryReason}${confidenceText}`,
      [RiskLevel.DANGEROUS]: `ВЫСОКИЙ РИСК: ${primaryReason}${confidenceText}`,
      [RiskLevel.SUSPICIOUS]: `СРЕДНИЙ РИСК: ${primaryReason}${confidenceText}`,
      [RiskLevel.LOW_RISK]: `НИЗКИЙ РИСК: ${primaryReason}${confidenceText}`,
      [RiskLevel.SAFE]: `БЕЗОПАСНО: ${primaryReason}${confidenceText}`,
    };

    return summaries[riskLevel] || `${typeText}: ${primaryReason}${confidenceText}`;
  }

  /**
   * Построение контекста для AI
   * @private
   */
  static buildAIContext(signals, score, level, activeSignals) {
    const sanitize = (text) => {
      if (!text) return 'N/A';
      return String(text)
        .replace(/[<>{}]/g, '')
        .replace(/\n/g, ' ')
        .substring(0, 200);
    };

    if (signals.type === 'url') {
      const signalsText = activeSignals
        .map(s => `  - ${s.source}: ${s.status}${s.details ? ' - ' + s.details : ''}`)
        .join('\n');

      return `Analyze this URL security assessment.

URL: ${sanitize(signals.url)}
Domain: ${sanitize(signals.domain)}

RISK ASSESSMENT:
- Score: ${score}/100
- Level: ${level}

SECURITY SIGNALS:
${signalsText}

Provide analysis in 3 parts (2-3 sentences each):
1. Risk Summary: What makes this URL risky or safe?
2. Potential Threats: What could happen?
3. Recommendation: Clear action for non-technical user.

Rules: Be direct, factual, use simple language. Do NOT mention AI or probabilities.`;
    } else {
      const signalsText = activeSignals
        .map(s => `  - ${s.source}: ${s.status}${s.details ? ' - ' + s.details : ''}`)
        .join('\n');

      return `Analyze this file security assessment.

FILE: ${sanitize(signals.filename)}
Size: ${signals.fileSize} bytes
Type: ${sanitize(signals.mimeType)}

RISK ASSESSMENT:
- Score: ${score}/100
- Level: ${level}

SECURITY SIGNALS:
${signalsText}

Provide analysis in 3 parts (2-3 sentences each):
1. Threat Assessment: What indicates malicious or safe?
2. Potential Impact: What could happen if executed?
3. Recommendation: Clear action for non-technical user.

Rules: Be technical but understandable. Do NOT mention AI.`;
    }
  }

  /**
   * Проверка, нужен ли AI анализ
   */
  static shouldUseAI(riskAssessment) {
    const { risk, analysis } = riskAssessment;

    // AI для критических и опасных случаев
    if (risk.level === RiskLevel.CRITICAL || risk.level === RiskLevel.DANGEROUS) {
      return true;
    }

    // AI для подозрительных с высокой оценкой
    if (risk.level === RiskLevel.SUSPICIOUS && risk.score >= 45) {
      return true;
    }

    // AI при множественных критических флагах
    if (analysis.criticalFlags.length >= 2) {
      return true;
    }

    // AI при низкой уверенности и среднем риске
    if (risk.confidence === ConfidenceLevel.LOW && risk.score >= 30) {
      return true;
    }

    // AI при несоответствии расширения (файлы)
    if (analysis.criticalFlags.includes('extension_mismatch') && risk.score >= 30) {
      return true;
    }

    return false;
  }

  /**
   * Валидация входных сигналов URL
   */
  static validateURLSignals(signals) {
    const errors = [];

    if (!signals.url) errors.push('URL is required');
    if (!signals.domain) errors.push('Domain is required');
    
    if (!signals.googleSafeBrowsing) {
      errors.push('Google Safe Browsing signal is required');
    } else if (!signals.googleSafeBrowsing.status) {
      errors.push('Google Safe Browsing status is required');
    }

    if (!signals.virusTotal) {
      errors.push('VirusTotal signal is required');
    } else if (!signals.virusTotal.status) {
      errors.push('VirusTotal status is required');
    }

    if (!signals.whois) {
      errors.push('WHOIS signal is required');
    } else if (!signals.whois.status) {
      errors.push('WHOIS status is required');
    }

    return errors;
  }

  /**
   * Валидация входных сигналов файла
   */
  static validateFileSignals(signals) {
    const errors = [];

    if (!signals.filename) errors.push('Filename is required');
    if (signals.fileSize === undefined) errors.push('File size is required');
    if (!signals.mimeType) errors.push('MIME type is required');

    if (!signals.virusTotal) {
      errors.push('VirusTotal signal is required');
    } else if (!signals.virusTotal.status) {
      errors.push('VirusTotal status is required');
    }

    if (!signals.staticAnalysis) {
      errors.push('Static analysis is required');
    }

    return errors;
  }

  /**
   * Валидация сигналов с выбросом ошибки
   */
  static validate(signals) {
    let errors = [];

    if (signals.type === 'url') {
      errors = this.validateURLSignals(signals);
    } else if (signals.type === 'file') {
      errors = this.validateFileSignals(signals);
    } else {
      errors.push('Invalid type: must be "url" or "file"');
    }

    if (errors.length > 0) {
      throw new Error(`Signal validation failed: ${errors.join(', ')}`);
    }
  }
}

/**
 * EXPORT
 */
module.exports = {
  RiskEngine,
  RiskLevel,
  ConfidenceLevel,
  SignalStatus,
  RISK_CONFIG,
};

/**
 * USAGE EXAMPLES
 */

/*
// Example 1: URL Risk Assessment
const urlSignals = {
  type: 'url',
  url: 'https://suspicious-site.xyz',
  domain: 'suspicious-site.xyz',
  googleSafeBrowsing: {
    status: 'danger',
    details: 'SOCIAL_ENGINEERING threat detected'
  },
  virusTotal: {
    status: 'suspicious',
    score: 3,
    details: '3/90 vendors flagged'
  },
  whois: {
    status: 'ok',
    domainAgeDays: 5,
    risk: 'critical'
  }
};

const urlAssessment = RiskEngine.assess(urlSignals);
console.log(urlAssessment);
// Output:
// {
//   risk: { score: 100, level: 'critical', confidence: 'high', confidenceScore: 100 },
//   analysis: {
//     signals: [...],
//     criticalFlags: ['google_safe_browsing_threat', 'domain_extremely_new'],
//     warnings: ['virustotal_suspicious', 'multiple_threat_sources'],
//     primaryReason: 'Flagged by Google Safe Browsing',
//     assessmentType: 'url'
//   },
//   recommendations: { user: '⛔ НЕ ОТКРЫВАЙТЕ...', ... },
//   summary: 'КРИТИЧЕСКИЙ РИСК: Flagged by Google Safe Browsing',
//   context: '...'
// }

// Example 2: File Risk Assessment
const fileSignals = {
  type: 'file',
  filename: 'document.pdf.exe',
  fileSize: 2048000,
  mimeType: 'application/x-msdownload',
  fileHash: 'abc123...',
  virusTotal: {
    status: 'danger',
    positives: 45,
    total: 70,
    percentage: 64
  },
  staticAnalysis: {
    fileExtension: '.exe',
    hasExecutableExtension: true,
    hasSuspiciousMimeType: true,
    extensionMismatch: true,
    entropy: 7.8,
    highEntropy: true,
    fileSignature: 'PDF'
  }
};

const fileAssessment = RiskEngine.assess(fileSignals);
console.log(fileAssessment);
// Output:
// {
//   risk: { score: 100, level: 'critical', confidence: 'high', confidenceScore: 100 },
//   analysis: {
//     signals: [...],
//     criticalFlags: ['virustotal_malware_detected', 'extension_mismatch'],
//     warnings: ['executable_file_type', 'suspicious_mime_type', ...],
//     primaryReason: 'Malware detected by antivirus engines',
//     assessmentType: 'file'
//   },
//   recommendations: { user: '⛔ НЕ ЗАПУСКАЙТЕ...', ... },
//   summary: 'КРИТИЧЕСКИЙ РИСК: Malware detected by antivirus engines',
//   context: '...'
// }

// Example 3: Check if AI analysis is needed
const needsAI = RiskEngine.shouldUseAI(urlAssessment);
console.log(needsAI); // true

// Example 4: Validation
try {
  const invalidSignals = { type: 'url' };
  RiskEngine.validate(invalidSignals);
} catch (error) {
  console.error(error.message);
  // "Signal validation failed: URL is required, Domain is required, ..."
}
*/