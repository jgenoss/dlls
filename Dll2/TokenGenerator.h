#ifndef TOKEN_GENERATOR_H
#define TOKEN_GENERATOR_H

#include <string>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <functional>

class TokenGenerator {
private:
    // Funci�n de hash simple pero efectiva
    static uint32_t simpleHash(const std::string& token) {
        uint32_t hash = 0;
        for (char c : token) {
            hash = hash * 31 + c;
        }
        return hash;
    }

public:
    // Generar token con marca de tiempo y hash
    static std::string generateSecureToken() {
        // Obtener marca de tiempo actual
        time_t now = time(nullptr);

        // Generar token base aleatorio
        std::string baseToken = generateBaseToken();

        // Convertir marca de tiempo a cadena
        std::string timeStr = std::to_string(now);

        // Combinar token base con marca de tiempo
        std::string fullToken = baseToken + timeStr;

        // Calcular hash de verificaci�n
        uint32_t tokenHash = simpleHash(fullToken);

        // Convertir hash a cadena hex
        std::string hashStr = intToHexString(tokenHash);

        // Token final: [BaseToken][MarcaTiempo][Hash]
        return fullToken + hashStr;
    }

    // Validar token
    static bool validateToken(const std::string& token) {
        // Verificar longitud m�nima
        if (token.length() < 20) return false;

        // Extraer partes del token
        std::string baseToken = token.substr(0, 10);
        std::string timeStr = token.substr(10, 10);
        std::string providedHash = token.substr(20);

        // Verificar base token
        if (!esTokenValido(baseToken)) return false;

        // Verificar marca de tiempo (no m�s de 1 hora de antig�edad)
        time_t tokenTime = std::stoll(timeStr);
        time_t currentTime = time(nullptr);
        if (std::abs(currentTime - tokenTime) > 3600) return false;

        // Recalcular y verificar hash
        std::string fullToken = baseToken + timeStr;
        uint32_t calculatedHash = simpleHash(fullToken);
        std::string calculatedHashStr = intToHexString(calculatedHash);

        return calculatedHashStr == providedHash;
    }

private:
    // Generar token base alfanum�rico
    static std::string generateBaseToken() {
        const std::string caracteresValidos =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::string token;
        for (int i = 0; i < 10; ++i) {
            token += caracteresValidos[rand() % caracteresValidos.length()];
        }

        return token;
    }

    // Convertir entero a cadena hexadecimal
    static std::string intToHexString(uint32_t value) {
        char buffer[9];
        snprintf(buffer, sizeof(buffer), "%08x", value);
        return std::string(buffer);
    }

    // Validaci�n de token base
    static bool esTokenValido(const std::string& token) {
        if (token.length() != 10) return false;

        bool tieneNumero = false;
        bool tieneMayuscula = false;
        bool tieneMinuscula = false;

        for (char c : token) {
            if (!std::isalnum(c)) return false;
            if (std::isdigit(c)) tieneNumero = true;
            if (std::isupper(c)) tieneMayuscula = true;
            if (std::islower(c)) tieneMinuscula = true;
        }

        return tieneNumero && tieneMayuscula && tieneMinuscula;
    }
};
#endif // TOKEN_GENERATOR_H