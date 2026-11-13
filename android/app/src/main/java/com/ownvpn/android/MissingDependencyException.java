package com.ownvpn.android;
final class MissingDependencyException extends IllegalStateException {
    final String option, reference;
    MissingDependencyException(String option, String reference) {
        super("缺少 " + option + " 依赖文件：" + reference);
        this.option = option;
        this.reference = reference;
    }
}
