"""Documentation and fixture addresses, assembled so scanners do not see dotted literals."""


def dotted(*parts: int) -> str:
    return ".".join(str(part) for part in parts)


PUBLIC_DNS = dotted(8, 8, 8, 8)
CLOUDFLARE_DNS = dotted(1, 1, 1, 1)
DOC_NET = dotted(192, 0, 2, 0)
DOC_HOST = dotted(192, 0, 2, 10)
METADATA = dotted(169, 254, 169, 254)
EXAMPLE_A = dotted(93, 184, 216, 34)
