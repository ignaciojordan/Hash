#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#include "hash.h"
#include "testing.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#define HASH_TAM 157
#define CARGA_MAX 0.7
#define CARGA_MIN 0.25
#define EXPANCION 2 //usar para el nuevo hash, si achicas hace hash->tamanio/2 si agrandas hash->tamanio*2

//Funcion de hashing "Kerrigan and Ritchie"

size_t hash_multiplicative(const char* clave, const hash_t* hash) {
	size_t key = 0;
	size_t largo = strlen(clave);
	for(size_t i = 0; i < largo; ++i){
		key = 131 * key + clave[i];
	}
	return key % hash->tamanio;
}
//Funcion auxiliar para buscar la posicion de una clave
//De no estar en la posicion que indica la funcion de hashing
//Devuelve  la primer posicion libre

//Funcion auxiliar para buscar la posicion de una clave
//De no estar en la posicion que indica la funcion de hashing
//Devuelve  la primer posicion libre

size_t buscar_posicion(const char* clave, const hash_t* hash){
	size_t buscado = hash_multiplicative(clave, hash);
	while(hash->tabla[buscado].clave){
		if(strcmp(clave, hash->tabla[buscado].clave) == 0){
			return buscado;
		}
		if (buscado == hash->tamanio -1){
			buscado = 0;
		}
		else{
			buscado++;
		}
	}
	return buscado;
}

bool tabla_crear(hash_t* hash, size_t tam){
	hash->tabla = malloc(tam * sizeof(campo_hash_t));
	if (!hash->tabla){
		free(hash);
		return false;
	}
	hash->tamanio = tam;
	hash->cantidad = 0;
	for (int i = 0; i < tam; i++){
		hash->tabla[i].estado = VACIO;
		hash->tabla[i].clave = NULL;
	}
	return true;
}
//Funcion auxiliar para redomensionar el hash

bool hash_redimensionar(hash_t* hash, size_t tam) {

	campo_hash_t* tabla = hash->tabla;
	size_t tamViejo = hash->tamanio;
	/*campo_hash_t* tabla_nueva = calloc(tam, sizeof(campo_hash_t));
	if (!tabla_nueva) {
		return false;
	}
	size_t tamViejo = hash->tamanio;
	hash->tabla = tabla_nueva;
	hash->tamanio = tam;
	hash->cantidad = 0;*/
	if (!tabla_crear(hash, tam)){
		return false;
	}
	for(size_t i = 0; i < tamViejo; i++ ) {
		if(tabla[i].estado == OCUPADO) {
			if (!hash_guardar(hash,tabla[i].clave, tabla[i].dato)){
				free(hash->tabla);
				hash->tabla = tabla;
				return false;
			}
		}
		free(tabla[i].clave);
	}
	free(tabla);
	return true;
}

//Primitivas Hash
hash_t *hash_crear(hash_destruir_dato_t destruir_dato){
	hash_t* hash = malloc(sizeof(hash_t));
	if (!hash){
		return NULL;
	}
	if (!tabla_crear(hash, HASH_TAM)){
		return NULL;
	}
	hash->destructor = destruir_dato;
	return hash;
}

size_t hash_cantidad(const hash_t *hash){
	return hash->cantidad;
}

bool hash_pertenece(const hash_t *hash, const char *clave){
	size_t posicion = buscar_posicion(clave, hash);
	if (hash->tabla[posicion].estado != OCUPADO){
		return false;
	}
	return true;
}

void* hash_obtener(const hash_t* hash, const char* clave){
    size_t pos = buscar_posicion(clave,hash);
    if (hash->tabla[pos].estado == VACIO || hash->tabla[pos].estado == BORRADO){ 
        return NULL;
    }
    return hash->tabla[pos].dato; 
}

void hash_destruir(hash_t *hash) {
	for (size_t i = 0; i < hash->tamanio; i++) {
		if ((hash->destructor != NULL)&&(hash->tabla[i].estado == OCUPADO)){
            void* elemento_a_borrar = hash->tabla[i].dato;
            hash->destructor(elemento_a_borrar);
        }
		free(hash->tabla[i].clave);
    }
	free(hash->tabla);
	free(hash);
}

void *hash_borrar(hash_t *hash, const char *clave) {
	/*if (!hash_pertenece(hash, clave)){
        return NULL;
    }*/
	size_t posicion = buscar_posicion(clave,hash);
	if (hash->tabla[posicion].estado == VACIO || hash->tabla[posicion].estado == BORRADO){
		return NULL;
	}
	void * valor = hash->tabla[posicion].dato;
	hash->tabla[posicion].dato = NULL;
	hash->tabla[posicion].estado = BORRADO;
	hash->cantidad--;
	if((float)hash->cantidad/(float)hash->tamanio <= CARGA_MIN){
		if(!hash_redimensionar(hash,hash->tamanio/EXPANCION)) {
			return valor;
		}
    }
	return valor;
}


bool hash_guardar(hash_t *hash, const char *clave, void *dato){
	size_t posicion = buscar_posicion(clave, hash);
	if(hash->tabla[posicion].estado == OCUPADO ){
        if (hash->destructor){
            void* borrar = hash->tabla[posicion].dato;
            hash->destructor(borrar);
        }
    } else {
		char* aux =strdup(clave);
        hash->cantidad++;
		hash->tabla[posicion].clave = aux;
		hash->tabla[posicion].estado = OCUPADO;
    }
	
	hash->tabla[posicion].dato = dato;
    if((float)hash->cantidad/(float)hash->tamanio >= CARGA_MAX){
		if (!hash_redimensionar(hash,hash->tamanio*EXPANCION)) {
			return false;
		}
	}
	return true;
}


// Crea iterador

bool hash_iter_avanzar(hash_iter_t *iter) {

	if (hash_iter_al_final (iter) ) return false;

	iter->actual++;
	while ((iter->actual < iter->hash->tamanio)&&
			(iter->hash->tabla[iter->actual].clave == NULL)) {
		iter->actual++;
	}
	return true;
}

hash_iter_t *hash_iter_crear(const hash_t *hash) {

	if (hash == NULL) return NULL;

	hash_iter_t* iterador = malloc( sizeof(hash_iter_t));
	if(iterador == NULL) return NULL;

	iterador->actual = 0;
	iterador->hash = hash;

	hash_iter_avanzar( iterador);
	return iterador;
}


const char* hash_iter_ver_actual(const hash_iter_t *iter){

	if (hash_iter_al_final (iter) ) {
		return NULL;
	}
	return  iter->hash->tabla[iter->actual].clave;
}

bool hash_iter_al_final(const hash_iter_t *iter) {
	return iter->actual == iter->hash->tamanio;
}

void hash_iter_destruir(hash_iter_t* iter){

	free(iter);
}
