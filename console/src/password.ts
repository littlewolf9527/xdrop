import { ref } from 'vue'

export const passwordOpen = ref(false)
export function openPassword() { passwordOpen.value = true }
