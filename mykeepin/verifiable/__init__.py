from abc import ABCMeta


class Verifiable(metaclass=ABCMeta):
    def __init__(self, id_=None, types=None, contexts=None):
        if types is None:
            types = []
        if contexts is None:
            contexts = {"@context": ["https://w3id.org/credentials/v1"]}

        self.id_ = id_
        self.types = types
        self.contexts = contexts

    @property
    def id_(self) -> str:
        return self._id

    @id_.setter
    def id_(self, i: str):
        if i is not None:
            if not isinstance(i, str):
                raise ValueError("'id'의 데이터는 str 이어야 합니다.")
        self._id = i

    @property
    def types(self) -> [str]:
        return self._types

    @types.setter
    def types(self, t: [str]):
        for data in t:
            if not isinstance(data, str):
                raise ValueError("'types'의 데이터는 str 이어야 합니다.")
        self._types = t

    @property
    def contexts(self) -> dict:
        return self._contexts

    @contexts.setter
    def contexts(self, c: dict):
        if not isinstance(c, dict):
            raise ValueError("'contexts'는 dict 이어야 합니다.")
        self._contexts = c
