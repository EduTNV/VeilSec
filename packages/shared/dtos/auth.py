from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    lgpd_consent: bool = Field(description="Aceite obrigatório dos termos.")
    model_config = {"str_strip_whitespace": True}


class RegisterResponse(BaseModel):
    client_id: str
    message: str = "Conta criada com sucesso."


class CreateAPIKeyResponse(BaseModel):
    key_id: str
    raw_key: str
    message: str = "Guarde esta chave em local seguro. Ela não será exibida novamente."


class RevokeAPIKeyResponse(BaseModel):
    key_id: str
    message: str = "Chave revogada com sucesso."


class ConsentRequest(BaseModel):
    lgpd_consent: bool
    consent_version: str
