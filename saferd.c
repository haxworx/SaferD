/*

  Copyright (c) 2014, Al Poole <al.poole@outlook.com>


  Permission to use, copy, modify, and/or distribute this software for any 
  purpose with or without fee is hereby granted, provided that the above 
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY 
  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, 
  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
  PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>

#define EVENT_BUF_LEN (16 + sizeof (struct inotify_event) * 1024)

#define SLASH "/"
#include <openssl/sha.h>

#define BUFSIZE 65535

typedef struct file_t file_t;
struct file_t {
        char path[PATH_MAX]; // PATH_MAX is a bit of an illusion
			     // Can go OOB.
        unsigned char sha1[1 + SHA_DIGEST_LENGTH * 2]; // double hex
        file_t *next;           // simple linked list
};

int early_exit;

void CatchSignals(int sig)
{
	if (sig == SIGTERM)
		early_exit = 1;

}

file_t * FileStoreDetails(file_t * files, char *path, unsigned char *sha1, int age);

void Error(char *fmt, ...);

#define STATEFILE "STATE"
void Chomp(char *str)
{
	char *p = str;

	while (*p) {
		if (*p == '\n') {
			*p = '\0';
			break;
		}
		p++;
	}
}
int LoadState(file_t *files)
{
	FILE *f = fopen(STATEFILE, "r");
	if (f == NULL)
		return 0;
	char buf[1024] = { 0 };
	char *path = NULL;
	
	while((fgets(buf, sizeof(buf), f)) != NULL) {
		Chomp(buf);
		path = strchr(buf, ' ');
		*path = '\0';
		++path;
        	files = FileStoreDetails(files, path, (unsigned char*) buf, 0);
	}


	fclose(f);

	return 1;
}


void SaveState(file_t *files)
{
	FILE *f = fopen(STATEFILE, "w");
	if (f == NULL)
		Error("fopen %s\n", strerror(errno));
	
	file_t *c = files->next;

	while (c) {
		fprintf(f, "%s %s\n", c->sha1, c->path);
		fflush(f);
		c = c->next;
	}
	
	fclose(f);
}

void Error(char *fmt, ...)
{
        char message[8192] = { 0 };
        va_list ap;

        va_start(ap, fmt);
        vsprintf(message, fmt, ap);
        fprintf(stderr, "Error: %s\n", message);
        va_end(ap);

        exit(EXIT_FAILURE);
}

void CollectSHAFromFile(file_t * files, char *path, unsigned long int size);

#define DIR_CREATED 0x01
#define DIR_DELETED 0x02
#define FILE_CREATED 0x03
#define FILE_DELETED 0x04

#define HOOKS_DIR "hooks"
#define HOOKS_FILE_CREATED "FileCreated.sh"
#define HOOKS_FILE_DELETED "FileDeleted.sh"
#define HOOKS_DIR_CREATED "DirCreated.sh"
#define HOOKS_DIR_DELETED "DirDeleted.sh"

void RemoveSHAFromMem(file_t *files, char *path)
{
	if (path == NULL)
		return; 

	file_t *c = files->next;
	file_t *prev = NULL;
	while (c->next && strcmp(c->path, path)) {
		prev = c;
		c = c->next;
	}
	if (c->next && 0 == strcmp(c->path, path)) {
		file_t *tmp = c;
		prev->next = c->next;
		free(tmp);
	} else if (c->next == NULL && 0 == strcmp(c->path, path)) {
		file_t *tmp = c;
		prev->next = NULL;
		free(tmp);
		
	}
}	

int ReactToChanges(file_t *files, char *path, int change)
{
	int result = 0;
	char exec_path[PATH_MAX] = { 0 };
	struct stat fstats;

	switch(change) {
		case DIR_CREATED:
			sprintf(exec_path, "%s %s", HOOKS_DIR_CREATED, path);
		break;
			
		case DIR_DELETED:
			sprintf(exec_path, "%s %s", HOOKS_DIR_DELETED, path);
		break;

		case FILE_CREATED:	
			stat(path, &fstats);
			sprintf(exec_path, "%s %s", HOOKS_FILE_CREATED, path);
                        CollectSHAFromFile(files, path, fstats.st_size);
		break;

		case FILE_DELETED:
			RemoveSHAFromMem(files, path);
			sprintf(exec_path, "%s %s", HOOKS_FILE_DELETED, path);
		break;
	};	

	char script_path[PATH_MAX] = { 0 };

	sprintf(script_path, "%s/%s %s", HOOKS_DIR, exec_path, path);

	if (change)
		system(script_path);

	return result;
}



int EventHandler(file_t * files, char *path, struct inotify_event *event)
{
        char change_path[PATH_MAX] = { 0 };
	int result = 0;

        sprintf(change_path, "%s/%s", path, event->name);

	int change = 0x00;

        if (event->mask & IN_CREATE) {
                if (event->mask & IN_ISDIR)
			change = DIR_CREATED;
                else
			change = FILE_CREATED;
        } else if (event->mask & IN_DELETE) {
                if (event->mask & IN_ISDIR)
			change = DIR_DELETED;
                else	
			change = FILE_DELETED;
        }

	if (event)
		result = ReactToChanges(files, change_path, change);

        return result;
}

int WatchDirs(file_t * files, char **dirs, int len)
{
        int length, i;
        char buf[EVENT_BUF_LEN];
        fd_set fds;
        int fd[len];
        int wd[len];
        struct timeval tm;
        struct inotify_event *event = NULL;

        FD_ZERO(&fds);


        for (i = 0; i < len; i++) {
                fd[i] = inotify_init1(IN_NONBLOCK);
                if (fd[i] < 0)
                        Error("inotify_init() %s", strerror(errno));

                wd[i] =
                    inotify_add_watch(fd[i], dirs[i],
                                      IN_CREATE | IN_DELETE);
        }
	int count; // test run
        for (count = 0; count < 100; count++) {

		if (early_exit == 1)
			return 1;

		puts("PING");

                int i = 0;
                for (i = 0; i < len; i++)
                        FD_SET(fd[i], &fds);    // select modifiies so repeat.

                tm.tv_sec = 1;
                tm.tv_usec = 0;
                int res = select(fd[len - 1] + 1, &fds, NULL, NULL, &tm);
                if (res < 0)
                        Error("select()");

                for (i = 0; i < len; i++) {
                        if (FD_ISSET(fd[i], &fds)) {
                                length = read(fd[i], buf, EVENT_BUF_LEN);
                                if (length <= 0) {
                                        Error("read()");
                                }

                                event = (struct inotify_event *) &buf;
                                if (event->len) {
					char path[PATH_MAX] = { 0 };
					sprintf(path, "%s", dirs[i]);
                                        EventHandler(files, path,
                                                     event);
				}
                        }

                }
        }

        for (i = 0; i < len; i++) {
                inotify_rm_watch(fd[i], wd[i]);
                close(fd[i]);
        }

        return 0;
}


file_t * FileStoreDetails(file_t * files, char *path, unsigned char *sha1, int age)
{

        file_t *c = files;
	if (c->next == NULL)
		puts("NULL");
	while (c->next) // FIX ME?
		c = c->next;
        if (c->next == NULL) {
                c->next = calloc(1, sizeof(file_t));
                if (c == NULL)
                        Error("malloc()");
		c = c->next;
                c->next = NULL;
                sprintf(c->path, "%s", path);
		int i;
		if (age) {
			for (i = 0; i < SHA_DIGEST_LENGTH; i++)	
				sprintf((char *)c->sha1, "%s%02x", (char *)c->sha1,(unsigned int) sha1[i]);
		} else
			sprintf((char *)c->sha1, "%s", sha1);

                return files;
        }

        Error("FileStoreDetails oops!");
	
	return files;
}

void CollectSHAFromFile(file_t * files, char *path, unsigned long int size)
{
        FILE *f = fopen(path, "r");
        if (f == NULL)
                Error("fopen() %s", strerror(errno));

#define CHUNK 512
        char line[CHUNK] = { 0 };

        unsigned char result[SHA_DIGEST_LENGTH] = { 0 }; // whoa
        SHA_CTX ctx;
	
        SHA1_Init(&ctx);

        size_t len = 0;
	
	do {
		len = fread(line, 1, CHUNK, f);
		if (len) {
        		SHA1_Update(&ctx, line, len);
		}
		memset(line, 0, CHUNK);
	} while (len > 0);
		
	SHA1_Final(result, &ctx);

        fclose(f);
        FileStoreDetails(files, path, result, 1);
}

int GetSHA(char *dirs, file_t * files)
{
//        char *directories[8192] = { NULL };
        DIR *d;
        struct dirent *dirent;
//	int i = 0;
	if (dirs == NULL)
		return 1;
	printf("DIRS IS %s\n", dirs);
        d = opendir(dirs);
        if (d == NULL)
                Error("opendir()");
//        int j = 0;

        while ((dirent = readdir(d)) != NULL) {
                if (!strcmp(dirent->d_name, "..")
                    || !strcmp(dirent->d_name, ".")) {
                        continue;
                }
                char path[PATH_MAX] = { 0 };
                sprintf(path, "%s/%s", dirs, dirent->d_name);
                struct stat fstats;
                stat(path, &fstats);
                if (S_ISDIR(fstats.st_mode)) {
 //                       directories[j++] = strdup(path);

                } else {
                        printf("File %s\n", path);
                        CollectSHAFromFile(files, path, fstats.st_size);
                }
        }

/*
	DONT USE THIS AS INOTIFY DOESNT WORK like this
 	while (directories[i] != NULL) {        
        	GetSHA(directories[i], files);
                free(directories[i--]);
                closedir(d);
        }
*/
	closedir(d);

        return 0;
}


int main(int argc, char **argv)
{
        char *directories[8192] = { NULL };
        int i = 0;
	
	if (argc <= 1) {
		printf("Usage: saferd [dir1] [dir2] ... \n");
		exit(EXIT_FAILURE);
	}
	
	for (i = 0; i < argc; i++)
		directories[i] = argv[i + 1];
		

        file_t *files = calloc(1, sizeof(file_t *));
	early_exit = 0; 

	signal(SIGTERM, CatchSignals); 
	
	int previous = LoadState(files);
	if (previous == 0) // first run
        	for (i = 0; i < argc + 1; i++)
                	GetSHA(directories[i], files);

        WatchDirs(files, directories, argc + 1);

	SaveState(files);

        return EXIT_SUCCESS;
}
