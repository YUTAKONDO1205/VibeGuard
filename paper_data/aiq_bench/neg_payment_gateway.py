import abc


class PaymentGateway(abc.ABC):
    @abc.abstractmethod
    def charge(self, amount_cents: int, token: str) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def refund(self, charge_id: str) -> str:
        raise NotImplementedError


class StripeGateway(PaymentGateway):
    def charge(self, amount_cents, token):
        return self._client.charges.create(amount=amount_cents, source=token).id

    def refund(self, charge_id):
        return self._client.refunds.create(charge=charge_id).id
