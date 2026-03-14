package com.deezyWallet.auth_service.dto;

import java.util.List;
import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ErrorDetail {
    private  String errorCode;
    private  String errorMessage;
    private  List<FieldErrorDetail> errors;

    public ErrorDetail(String errorCode, String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ErrorDetail that)) {
            return false;
        }
        return Objects.equals(errorCode, that.errorCode)
                && Objects.equals(errorMessage, that.errorMessage)
                && Objects.equals(errors, that.errors);
    }

    @Override
    public int hashCode() {
        return Objects.hash(errorCode, errorMessage, errors);
    }

    @Override
    public String toString() {
        return "ErrorDetail{" +
                "errorCode='" + errorCode + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                ", errors=" + errors +
                '}';
    }
}
