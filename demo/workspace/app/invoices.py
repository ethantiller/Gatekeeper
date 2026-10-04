"""Invoice totals."""

TAX_RATE = 0.08


def subtotal(lines: list[tuple[str, int, float]]) -> float:
    return round(sum(quantity * price for _, quantity, price in lines), 2)


def total(lines: list[tuple[str, int, float]]) -> float:
    return round(subtotal(lines) * (1 + TAX_RATE), 2)
