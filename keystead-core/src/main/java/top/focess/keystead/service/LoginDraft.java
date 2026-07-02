package top.focess.keystead.service;

import top.focess.keystead.memory.SecretBuffer;

public interface LoginDraft {

    LoginDraft title(String title);

    LoginDraft tag(String tag);

    LoginDraft username(SecretBuffer username);

    LoginDraft password(SecretBuffer password);

    LoginDraft url(String url);

    LoginDraft notes(SecretBuffer notes);
}
