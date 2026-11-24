from contextvars import ContextVar

current_user_sub: ContextVar[str] = ContextVar("current_user_sub", default="local")
