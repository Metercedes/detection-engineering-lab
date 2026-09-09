"""Parser for the Sigma ``condition`` expression.

Grammar:

    expression := term (("or" | "and") term)*
    term       := "not"? factor
    factor     := "(" expression ")" | quantifier | IDENTIFIER
    quantifier := ("1" | "all" | "any") "of" (IDENTIFIER | IDENTIFIER "*" | "them")

Precedence is ``not`` > ``and`` > ``or``, matching the Sigma specification.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from sigmatch.errors import RuleParseError

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*][A-Za-z0-9_*.-]*")


@dataclass(frozen=True)
class Identifier:
    name: str


@dataclass(frozen=True)
class Quantifier:
    mode: str
    pattern: str


@dataclass(frozen=True)
class Not:
    operand: object


@dataclass(frozen=True)
class And:
    operands: tuple


@dataclass(frozen=True)
class Or:
    operands: tuple


def tokenize(condition: str) -> list[str]:
    tokens = _TOKEN.findall(condition)
    if not tokens:
        raise RuleParseError(f"empty condition: {condition!r}")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise RuleParseError("unexpected end of condition")
        self.pos += 1
        return token

    def expect(self, expected: str) -> None:
        token = self.take()
        if token.lower() != expected:
            raise RuleParseError(f"expected {expected!r} but found {token!r}")

    def parse(self) -> object:
        node = self.expression()
        if self.peek() is not None:
            raise RuleParseError(f"trailing tokens in condition: {self.tokens[self.pos :]}")
        return node

    def expression(self) -> object:
        node = self.and_expression()
        operands = [node]
        while (token := self.peek()) and token.lower() == "or":
            self.take()
            operands.append(self.and_expression())
        return node if len(operands) == 1 else Or(tuple(operands))

    def and_expression(self) -> object:
        operands = [self.term()]
        while (token := self.peek()) and token.lower() == "and":
            self.take()
            operands.append(self.term())
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def term(self) -> object:
        if (token := self.peek()) and token.lower() == "not":
            self.take()
            return Not(self.term())
        return self.factor()

    def factor(self) -> object:
        token = self.take()
        if token == "(":
            node = self.expression()
            self.expect(")")
            return node
        lowered = token.lower()
        if lowered in ("1", "all", "any"):
            following = self.peek()
            if following and following.lower() == "of":
                self.take()
                target = self.take()
                mode = "all" if lowered == "all" else "any"
                return Quantifier(mode, target)
        if lowered in ("and", "or", "not", ")"):
            raise RuleParseError(f"unexpected token {token!r}")
        return Identifier(token)


def parse(condition: str) -> object:
    return _Parser(tokenize(condition)).parse()


def evaluate(node: object, results: dict[str, bool]) -> bool:
    """Evaluate a parsed condition against per-search-identifier results."""
    match node:
        case Identifier(name):
            if name not in results:
                raise RuleParseError(f"condition references unknown search identifier {name!r}")
            return results[name]
        case Not(operand):
            return not evaluate(operand, results)
        case And(operands):
            return all(evaluate(o, results) for o in operands)
        case Or(operands):
            return any(evaluate(o, results) for o in operands)
        case Quantifier(mode, pattern):
            selected = _select(pattern, results)
            if not selected:
                raise RuleParseError(f"quantifier {pattern!r} matched no search identifiers")
            return all(selected) if mode == "all" else any(selected)
    raise RuleParseError(f"unhandled condition node {node!r}")


def _select(pattern: str, results: dict[str, bool]) -> list[bool]:
    if pattern.lower() == "them":
        return list(results.values())
    return [value for name, value in results.items() if fnmatch.fnmatchcase(name, pattern)]
