package com.cos.jwt.dto;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;

public record UserDto(
        String username,
        String password
) {

    private static final ObjectMapper om = new ObjectMapper();

    public static UserDto from(InputStream inputStream) throws IOException {
        return om.readValue(inputStream, UserDto.class);
    }
}
