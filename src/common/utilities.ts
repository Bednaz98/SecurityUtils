export function convertStringToNumber(input: string): number {
    return input.split('').map((e) => e.charCodeAt(0)).reduce((a, b) => a + b)
}