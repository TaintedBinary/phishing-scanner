"""Evaluation of scanner decisions against a labeled URL dataset."""

import json
from typing import Dict, Iterable, List


POSITIVE_LEVELS = frozenset({'高风险', '钓鱼', '高置信钓鱼', '恶意软件', '诈骗', '已拦截'})
POSITIVE_LABELS = frozenset({'1', 'true', 'phishing', 'malicious', 'positive', '钓鱼', '恶意'})
NEGATIVE_LABELS = frozenset({'0', 'false', 'safe', 'benign', 'negative', '安全', '正常'})


def load_labeled_dataset(path: str) -> List[Dict[str, object]]:
    with open(path, 'r', encoding='utf-8-sig') as handle:
        payload = json.load(handle)
    records = payload.get('samples') if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise ValueError('评估数据集必须是非空数组或包含 samples 数组的对象')
    normalized = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValueError(f'评估数据集第 {index} 项必须是对象')
        url = str(record.get('url', '')).strip()
        if not url:
            raise ValueError(f'评估数据集第 {index} 项缺少 url')
        normalized.append({'url': url, 'positive': _parse_label(record.get('label'), index)})
    return normalized


def evaluate_detector(detector, samples: Iterable[Dict[str, object]],
                      max_workers: int = 2) -> Dict[str, object]:
    samples = list(samples)
    results = detector.batch_detect(
        [str(sample['url']) for sample in samples], max_workers=max_workers
    )
    counts = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0, 'errors': 0}
    decisions = []
    for sample, result in zip(samples, results):
        expected = bool(sample['positive'])
        level = result.get('risk_level', '检测失败')
        if level == '检测失败':
            counts['errors'] += 1
            decisions.append({
                'url': sample['url'],
                'expected': 'phishing' if expected else 'safe',
                'predicted': level,
                'score': result.get('total_score', 0),
                'correct': False,
                'error': result.get('error', ''),
            })
            continue
        predicted = level in POSITIVE_LEVELS
        if expected and predicted:
            counts['tp'] += 1
        elif expected:
            counts['fn'] += 1
        elif predicted:
            counts['fp'] += 1
        else:
            counts['tn'] += 1
        decisions.append({
            'url': sample['url'],
            'expected': 'phishing' if expected else 'safe',
            'predicted': level,
            'score': result.get('total_score', 0),
            'correct': expected == predicted,
            'error': result.get('error', ''),
        })

    tp, tn, fp, fn = (counts[key] for key in ('tp', 'tn', 'fp', 'fn'))
    evaluated = tp + tn + fp + fn
    return {
        'samples': len(samples),
        'evaluated': evaluated,
        'confusion_matrix': counts,
        'metrics': {
            'precision': _ratio(tp, tp + fp),
            'recall': _ratio(tp, tp + fn),
            'false_positive_rate': _ratio(fp, fp + tn),
            'false_negative_rate': _ratio(fn, fn + tp),
            'accuracy': _ratio(tp + tn, evaluated),
        },
        'decisions': decisions,
    }


def _parse_label(value, index: int) -> bool:
    normalized = str(value).strip().lower()
    if normalized in POSITIVE_LABELS:
        return True
    if normalized in NEGATIVE_LABELS:
        return False
    raise ValueError(f'评估数据集第 {index} 项 label 无效: {value!r}')


def _ratio(numerator: int, denominator: int):
    return round(numerator / denominator, 4) if denominator else None
